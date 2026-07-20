// Copyright (c) 2024-present TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/vault_signing.h>

#include <hash.h>
#include <logging.h>
#include <script/interpreter.h>
#include <streams.h>
#include <util/strencodings.h>

namespace wallet {

bool VaultSigningIntent::Validate() const
{
    // Purpose must be non-empty
    if (leaf_purpose.empty()) {
        return false;
    }

    // Tapleaf hash must be non-zero
    if (tapleaf_hash.IsNull()) {
        return false;
    }

    // Control block must be valid size (33 or 65 bytes typically)
    // 33 bytes: 1 (leaf_version & parity) + 32 (internal_key)
    // 65 bytes: 1 + 32 + 32 (one merkle proof element)
    // Can be longer for deeper trees (33 + 32*N)
    if (control_block.empty() || control_block.size() < 33 || (control_block.size() - 33) % 32 != 0) {
        return false;
    }

    return true;
}

bool VaultSigningIntent::operator==(const VaultSigningIntent& other) const
{
    return leaf_purpose == other.leaf_purpose &&
           tapleaf_hash == other.tapleaf_hash &&
           control_block == other.control_block &&
           signer_fingerprints == other.signer_fingerprints &&
           timelock_value == other.timelock_value;
}

std::string VaultInputTypeToString(VaultInputType type)
{
    switch (type) {
    case VaultInputType::FORWARD_VAULT_COOPERATIVE:
        return "forward_vault_cooperative";
    case VaultInputType::FORWARD_VAULT_TIMEOUT:
        return "forward_vault_timeout";
    case VaultInputType::FORWARD_VAULT_SELF_DELIVERY:
        return "forward_vault_self_delivery";
    case VaultInputType::REPO_VAULT_SETTLEMENT:
        return "repo_vault_settlement";
    case VaultInputType::REPO_VAULT_TIMEOUT:
        return "repo_vault_timeout";
    case VaultInputType::FUNDING_INPUT:
        return "funding_input";
    case VaultInputType::UNKNOWN:
    default:
        return "unknown";
    }
}

// Helper: Create BIP174 proprietary PSBT entry for vault intent
static PSBTProprietary MakeVaultIntentProp(std::span<const unsigned char> value)
{
    PSBTProprietary prop;
    prop.identifier.assign(PSBT_FS_IDENTIFIER, PSBT_FS_IDENTIFIER + 2); // "fs"
    prop.subtype = PSBT_FS_VAULT_INTENT_SUBTYPE;

    // Build the key according to BIP174:
    // type (0xFC) || compact_size(identifier_len) || identifier || compact_size(subtype) || keydata
    VectorWriter key_writer(prop.key, prop.key.size());
    WriteCompactSize(key_writer, PSBT_IN_PROPRIETARY);
    WriteCompactSize(key_writer, prop.identifier.size());
    key_writer.write(std::as_bytes(std::span(prop.identifier)));
    WriteCompactSize(key_writer, prop.subtype);
    // No keydata for this field

    prop.value.assign(value.begin(), value.end());
    return prop;
}

// Helper: Create BIP174 proprietary PSBT entry for input type
static PSBTProprietary MakeInputTypeProp(VaultInputType type)
{
    PSBTProprietary prop;
    prop.identifier.assign(PSBT_FS_IDENTIFIER, PSBT_FS_IDENTIFIER + 2); // "fs"
    prop.subtype = PSBT_FS_INPUT_TYPE_SUBTYPE;

    // Build the key according to BIP174
    VectorWriter key_writer(prop.key, prop.key.size());
    WriteCompactSize(key_writer, PSBT_IN_PROPRIETARY);
    WriteCompactSize(key_writer, prop.identifier.size());
    key_writer.write(std::as_bytes(std::span(prop.identifier)));
    WriteCompactSize(key_writer, prop.subtype);
    // No keydata for this field

    prop.value = {static_cast<uint8_t>(type)};
    return prop;
}

// Helper: Match proprietary entry by identifier and subtype
static bool MatchesFsEntry(const PSBTProprietary& entry, uint64_t subtype)
{
    return entry.identifier.size() == 2 &&
           entry.identifier[0] == 'f' &&
           entry.identifier[1] == 's' &&
           entry.subtype == subtype;
}

bool EmbedVaultIntent(PSBTInput& input, const VaultSigningIntent& intent)
{
    if (!intent.Validate()) {
        LogPrintf("EmbedVaultIntent: Invalid intent structure\n");
        return false;
    }

    try {
        // Serialize the intent
        DataStream ss{};
        ss << intent;

        // Convert DataStream to vector<unsigned char>
        std::vector<unsigned char> value;
        value.reserve(ss.size());
        for (auto byte : ss) {
            value.push_back(static_cast<unsigned char>(byte));
        }

        // Remove any existing vault intent entry
        auto it = input.m_proprietary.begin();
        while (it != input.m_proprietary.end()) {
            if (MatchesFsEntry(*it, PSBT_FS_VAULT_INTENT_SUBTYPE)) {
                it = input.m_proprietary.erase(it);
            } else {
                ++it;
            }
        }

        // Create and insert new proprietary entry
        PSBTProprietary prop = MakeVaultIntentProp(value);
        input.m_proprietary.insert(std::move(prop));

        LogPrintf("EmbedVaultIntent: Embedded intent for purpose '%s', leaf hash %s\n",
                 intent.leaf_purpose, intent.tapleaf_hash.ToString());
        return true;
    } catch (const std::exception& e) {
        LogPrintf("EmbedVaultIntent: Failed to serialize intent: %s\n", e.what());
        return false;
    }
}

std::optional<VaultSigningIntent> ExtractVaultIntent(const PSBTInput& input)
{
    // Search for vault intent in proprietary entries
    for (const auto& prop : input.m_proprietary) {
        if (MatchesFsEntry(prop, PSBT_FS_VAULT_INTENT_SUBTYPE)) {
            try {
                // Deserialize the intent
                SpanReader ss{prop.value};
                VaultSigningIntent intent;
                ss >> intent;

                if (!intent.Validate()) {
                    LogPrintf("ExtractVaultIntent: Deserialized intent failed validation\n");
                    return std::nullopt;
                }

                LogPrintf("ExtractVaultIntent: Extracted intent for purpose '%s'\n", intent.leaf_purpose.c_str());
                return intent;
            } catch (const std::exception& e) {
                LogPrintf("ExtractVaultIntent: Failed to deserialize intent: %s\n", e.what());
                return std::nullopt;
            }
        }
    }

    return std::nullopt;
}

bool EmbedInputType(PSBTInput& input, VaultInputType type)
{
    try {
        // Remove any existing input type entry
        auto it = input.m_proprietary.begin();
        while (it != input.m_proprietary.end()) {
            if (MatchesFsEntry(*it, PSBT_FS_INPUT_TYPE_SUBTYPE)) {
                it = input.m_proprietary.erase(it);
            } else {
                ++it;
            }
        }

        // Create and insert new proprietary entry
        PSBTProprietary prop = MakeInputTypeProp(type);
        input.m_proprietary.insert(std::move(prop));
        return true;
    } catch (const std::exception& e) {
        LogPrintf("EmbedInputType: Failed: %s\n", e.what());
        return false;
    }
}

VaultInputType ExtractInputType(const PSBTInput& input)
{
    for (const auto& prop : input.m_proprietary) {
        if (MatchesFsEntry(prop, PSBT_FS_INPUT_TYPE_SUBTYPE)) {
            if (!prop.value.empty()) {
                return static_cast<VaultInputType>(prop.value[0]);
            }
        }
    }

    return VaultInputType::UNKNOWN;
}

bool ValidateVaultIntent(const VaultMetadata& metadata,
                        const VaultSigningIntent& intent,
                        std::string& error)
{
    // 1. Find leaf with matching tapleaf hash
    const VaultLeafDescriptor* matching_leaf = nullptr;
    for (const auto& leaf : metadata.leaves) {
        // Compute tapleaf hash for this leaf
        // TapLeaf hash = TaggedHash("TapLeaf", leaf_version || script)
        uint256 computed_hash = (HashWriter{HASHER_TAPLEAF} << leaf.leaf_version << leaf.script).GetSHA256();

        if (computed_hash == intent.tapleaf_hash) {
            matching_leaf = &leaf;
            break;
        }
    }

    if (!matching_leaf) {
        error = strprintf("Vault intent specifies leaf hash %s, but no matching leaf found in metadata",
                         intent.tapleaf_hash.ToString());
        return false;
    }

    // 2. Validate leaf purpose matches
    if (matching_leaf->purpose != intent.leaf_purpose) {
        error = strprintf("Vault intent purpose '%s' does not match leaf purpose '%s'",
                         intent.leaf_purpose, matching_leaf->purpose);
        return false;
    }

    // 3. Validate control block
    // Control block format: leaf_version_with_parity || internal_key || merkle_proof
    if (intent.control_block.size() < 33) {
        error = strprintf("Invalid control block size: %d (minimum 33)", intent.control_block.size());
        return false;
    }

    // Extract internal key from control block
    XOnlyPubKey control_internal_key;
    std::copy(intent.control_block.begin() + 1, intent.control_block.begin() + 33,
              control_internal_key.begin());

    // Verify it matches the metadata's internal key
    if (control_internal_key != metadata.spenddata.internal_key) {
        error = strprintf("Control block internal key does not match vault metadata");
        return false;
    }

    // 4. Validate timelock consistency (if specified in both)
    if (intent.timelock_value.has_value() && matching_leaf->timelock.has_value()) {
        if (*intent.timelock_value != *matching_leaf->timelock) {
            error = strprintf("Intent timelock %d does not match leaf timelock %d",
                             *intent.timelock_value, *matching_leaf->timelock);
            return false;
        }
    }

    return true;
}

std::optional<VaultLeafDescriptor> SelectLeafByIntent(
    const VaultMetadata& metadata,
    const VaultSigningIntent& intent)
{
    std::string error;
    if (!ValidateVaultIntent(metadata, intent, error)) {
        LogPrintf("SelectLeafByIntent: Validation failed: %s\n", error.c_str());
        return std::nullopt;
    }

    // Find the matching leaf (we already validated it exists)
    for (const auto& leaf : metadata.leaves) {
        uint256 computed_hash = (HashWriter{HASHER_TAPLEAF} << leaf.leaf_version << leaf.script).GetSHA256();

        if (computed_hash == intent.tapleaf_hash) {
            return leaf;
        }
    }

    // Should never reach here if ValidateVaultIntent passed
    return std::nullopt;
}

bool ValidateTimelock(const VaultLeafDescriptor& leaf,
                     int chain_tip,
                     std::string& error)
{
    if (!leaf.timelock.has_value()) {
        // No timelock, always valid
        return true;
    }

    uint32_t timelock = *leaf.timelock;

    // Determine if this is CLTV or CSV based on purpose or script analysis
    // For now, assume CLTV if purpose contains "timeout"
    // (More robust: parse script to detect OP_CHECKLOCKTIMEVERIFY vs OP_CHECKSEQUENCEVERIFY)
    bool is_cltv = (leaf.purpose.find("timeout") != std::string::npos);

    if (is_cltv) {
        // CLTV: timelock is absolute block height or timestamp
        // Simple check: if timelock > 500000000, it's a timestamp; otherwise height
        if (timelock < 500000000) {
            // Block height
            if (chain_tip < static_cast<int>(timelock)) {
                error = strprintf("CLTV timelock not satisfied: current height %d < required %d",
                                 chain_tip, timelock);
                return false;
            }
        } else {
            // Timestamp - would need current time, skip for now
            // Caller should validate this separately with actual block time
            LogPrintf("ValidateTimelock: CLTV timestamp %d - caller must validate against block time\n", timelock);
        }
    } else {
        // CSV: timelock is relative, validated during transaction execution
        // Cannot pre-validate CSV without knowing the input's age
        LogPrintf("ValidateTimelock: CSV timelock %d - will be validated during execution\n", timelock);
    }

    return true;
}

std::optional<VaultSigningIntent> CreateCooperativeIntent(const VaultMetadata& metadata)
{
    // Find cooperative leaf
    for (const auto& leaf : metadata.leaves) {
        if (leaf.purpose == "cooperative") {
            return CreateIntentFromLeaf(leaf, metadata.spenddata);
        }
    }

    LogPrintf("CreateCooperativeIntent: No cooperative leaf found in metadata\n");
    return std::nullopt;
}

std::optional<VaultSigningIntent> CreateTimeoutIntent(
    const VaultMetadata& metadata,
    const std::string& purpose)
{
    // Find leaf with matching purpose
    for (const auto& leaf : metadata.leaves) {
        if (leaf.purpose == purpose) {
            return CreateIntentFromLeaf(leaf, metadata.spenddata);
        }
    }

    LogPrintf("CreateTimeoutIntent: No leaf with purpose '%s' found\n", purpose.c_str());
    return std::nullopt;
}

VaultSigningIntent CreateIntentFromLeaf(
    const VaultLeafDescriptor& leaf,
    const TaprootSpendData& spenddata)
{
    VaultSigningIntent intent;
    intent.leaf_purpose = leaf.purpose;

    // Compute tapleaf hash
    intent.tapleaf_hash = (HashWriter{HASHER_TAPLEAF} << leaf.leaf_version << leaf.script).GetSHA256();

    // Find control block from spenddata
    // spenddata.scripts is a map: (script, leaf_version) -> set<control_blocks>
    auto script_key = std::make_pair(leaf.script, static_cast<int>(leaf.leaf_version));
    auto it = spenddata.scripts.find(script_key);

    if (it != spenddata.scripts.end() && !it->second.empty()) {
        // Use the first control block (should only be one for well-formed trees)
        intent.control_block = *it->second.begin();
    } else {
        // Fallback: construct control block manually
        // Format: leaf_version_with_parity || internal_key || merkle_proof
        intent.control_block.clear();

        // First byte: leaf version (with parity bit, default to 0)
        intent.control_block.push_back(leaf.leaf_version);

        // Internal key (32 bytes)
        intent.control_block.insert(intent.control_block.end(),
                                    spenddata.internal_key.begin(),
                                    spenddata.internal_key.end());

        // Merkle proof would be needed here for multi-leaf trees
        // For now, warn if we couldn't find it in spenddata
        LogPrintf("CreateIntentFromLeaf: Warning - control block not found in spenddata, using minimal block\n");
    }

    // Copy timelock if present
    intent.timelock_value = leaf.timelock;

    return intent;
}

} // namespace wallet
