// Copyright (c) 2024-present TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/vaultregistry.h>

#include <addresstype.h>
#include <logging.h>
#include <script/interpreter.h>
#include <wallet/walletdb.h>

#include <algorithm>

namespace wallet {

std::string VaultRoleToString(VaultRole role)
{
    switch (role) {
        case VaultRole::REPO_BORROWER:  return "REPO_BORROWER";
        case VaultRole::REPO_LENDER:    return "REPO_LENDER";
        case VaultRole::FORWARD_LONG:   return "FORWARD_LONG";
        case VaultRole::FORWARD_SHORT:  return "FORWARD_SHORT";
        case VaultRole::FORWARD_ESCROW_B:return "FORWARD_ESCROW_B";
        case VaultRole::FORWARD_ESCROW_A:return "FORWARD_ESCROW_A";
        case VaultRole::DIFFICULTY_LONG: return "DIFFICULTY_LONG";
        case VaultRole::DIFFICULTY_SHORT:return "DIFFICULTY_SHORT";
    }
    return "UNKNOWN";
}

// ============================================================================
// VaultBuilder Implementation
// ============================================================================

std::optional<VaultMetadata> VaultBuilder::Build(
    const TaprootBuilder& builder,
    const uint256& contract_id,
    VaultRole role,
    const std::vector<VaultLeafDescriptor>& leaf_metadata)
{
    // Validate builder state
    if (!builder.IsValid() || !builder.IsComplete()) {
        LogPrintf("VaultBuilder::Build: Builder is invalid or incomplete\n");
        return std::nullopt;
    }

    // Extract TaprootSpendData from builder
    TaprootSpendData spenddata = builder.GetSpendData();

    // Validate spenddata
    if (!spenddata.internal_key.IsFullyValid()) {
        LogPrintf("VaultBuilder::Build: Invalid internal key in spenddata\n");
        return std::nullopt;
    }

    if (spenddata.scripts.empty()) {
        LogPrintf("VaultBuilder::Build: No scripts in spenddata\n");
        return std::nullopt;
    }

    // Validate all leaf_metadata entries match scripts in spenddata
    for (const auto& leaf : leaf_metadata) {
        if (!leaf.Validate()) {
            LogPrintf("VaultBuilder::Build: Invalid leaf descriptor for %s\n", leaf.purpose);
            return std::nullopt;
        }

        auto script_key = std::make_pair(leaf.script, static_cast<int>(leaf.leaf_version));
        if (spenddata.scripts.find(script_key) == spenddata.scripts.end()) {
            LogPrintf("VaultBuilder::Build: Leaf '%s' not found in spenddata.scripts\n", leaf.purpose);
            return std::nullopt;
        }
    }

    // Construct VaultMetadata
    VaultMetadata metadata;
    metadata.version = VaultMetadata::CURRENT_VERSION;
    metadata.spenddata = std::move(spenddata);
    metadata.leaves = leaf_metadata;
    metadata.contract_id = contract_id;
    metadata.role = role;

    // Validate complete metadata
    if (!metadata.Validate()) {
        LogPrintf("VaultBuilder::Build: Final metadata validation failed\n");
        return std::nullopt;
    }

    return metadata;
}

VaultLeafDescriptor VaultBuilder::CreateLeaf(
    const CScript& script,
    const XOnlyPubKey& signing_key,
    const std::string& purpose,
    std::optional<uint32_t> timelock)
{
    VaultLeafDescriptor leaf;
    leaf.script = std::vector<unsigned char>(script.begin(), script.end());
    leaf.leaf_version = TAPROOT_LEAF_TAPSCRIPT;
    leaf.signing_key = signing_key;
    leaf.purpose = purpose;
    leaf.timelock = timelock;
    return leaf;
}

// ============================================================================
// VaultLeafDescriptor Implementation
// ============================================================================

bool VaultLeafDescriptor::Validate() const
{
    // Validate x-only key format (must be 32 bytes)
    if (signing_key.size() != 32) {
        LogPrintf("VaultLeafDescriptor::Validate: Invalid signing_key size (%d bytes)\n", signing_key.size());
        return false;
    }

    // A covenant-only leaf (all-zero signing_key sentinel) is signatureless / keeper-spendable, so it
    // has no key to validate. A non-covenant leaf must carry a fully-valid x-only signing key.
    if (!IsCovenantOnly() && !signing_key.IsFullyValid()) {
        LogPrintf("VaultLeafDescriptor::Validate: signing_key failed IsFullyValid()\n");
        return false;
    }

    // Validate leaf version (should be TAPROOT_LEAF_TAPSCRIPT = 0xc0)
    if (leaf_version != TAPROOT_LEAF_TAPSCRIPT) {
        LogPrintf("VaultLeafDescriptor::Validate: Invalid leaf_version (0x%02x)\n", leaf_version);
        return false;
    }

    // Script must not be empty
    if (script.empty()) {
        LogPrintf("VaultLeafDescriptor::Validate: Empty script\n");
        return false;
    }

    // Purpose must not be empty
    if (purpose.empty()) {
        LogPrintf("VaultLeafDescriptor::Validate: Empty purpose\n");
        return false;
    }

    return true;
}

// ============================================================================
// VaultMetadata Implementation
// ============================================================================

XOnlyPubKey VaultMetadata::GetOutputKey() const
{
    // Use cached value if available
    if (cached_output_key.has_value()) {
        return *cached_output_key;
    }

    // Compute from spenddata
    // The output key is internal_key tweaked with merkle_root
    XOnlyPubKey internal = spenddata.internal_key;
    uint256 merkle = spenddata.merkle_root;

    // Tweak the internal key with the merkle root
    // Formula: output_key = internal_key + hash(internal_key || merkle_root)
    auto tweak_result = internal.CreateTapTweak(merkle.IsNull() ? nullptr : &merkle);
    if (!tweak_result) {
        LogPrintf("VaultMetadata::GetOutputKey: Failed to create tap tweak\n");
        return XOnlyPubKey();
    }

    XOnlyPubKey output = tweak_result->first;

    // Cache for future calls
    cached_output_key = output;
    return output;
}

CScript VaultMetadata::GetScriptPubKey() const
{
    // Use cached value if available
    if (cached_scriptPubKey.has_value()) {
        return *cached_scriptPubKey;
    }

    // Get output key and construct P2TR scriptPubKey
    XOnlyPubKey output_key = GetOutputKey();
    WitnessV1Taproot taproot_output{output_key};

    // Create script: OP_1 <32-byte output key>
    CScript spk = GetScriptForDestination(taproot_output);

    // Cache for future calls
    cached_scriptPubKey = spk;
    return spk;
}

bool VaultMetadata::Validate() const
{
    // 1. Check version
    if (version != CURRENT_VERSION) {
        LogPrintf("VaultMetadata::Validate: Unsupported version %u\n", version);
        return false;
    }

    // 2. Internal key must be valid
    if (!spenddata.internal_key.IsFullyValid()) {
        LogPrintf("VaultMetadata::Validate: Invalid internal_key\n");
        return false;
    }

    // 3. All leaves must be valid
    if (leaves.empty()) {
        LogPrintf("VaultMetadata::Validate: No leaves defined\n");
        return false;
    }

    for (const auto& leaf : leaves) {
        if (!leaf.Validate()) {
            return false;
        }
    }

    // 4. All leaves must be present in spenddata.scripts
    for (const auto& leaf : leaves) {
        auto script_key = std::make_pair(leaf.script, static_cast<int>(leaf.leaf_version));
        if (spenddata.scripts.find(script_key) == spenddata.scripts.end()) {
            LogPrintf("VaultMetadata::Validate: Leaf '%s' not found in spenddata.scripts\n", leaf.purpose);
            return false;
        }
    }

    // 5. Contract ID must not be null
    if (contract_id.IsNull()) {
        LogPrintf("VaultMetadata::Validate: Null contract_id\n");
        return false;
    }

    return true;
}

TaprootBuilder VaultMetadata::RebuildBuilder() const
{
    TaprootBuilder builder;

    // Attempt to recover the original tree layout from the stored spenddata.
    const XOnlyPubKey output_key = GetOutputKey();
    const auto inferred = InferTaprootTree(spenddata, output_key);
    if (!inferred) {
        LogPrintf("VaultMetadata::RebuildBuilder: Unable to infer taproot tree for contract %s\n",
                  contract_id.ToString());
        return builder;
    }

    for (const auto& [depth, script, leaf_ver] : *inferred) {
        builder.Add(depth, script, leaf_ver, /*track=*/true);
    }

    if (!builder.IsValid() || !builder.IsComplete()) {
        LogPrintf("VaultMetadata::RebuildBuilder: Incomplete builder for contract %s\n",
                  contract_id.ToString());
        return TaprootBuilder{};
    }

    builder.Finalize(spenddata.internal_key);

    if (!builder.IsValid() || !builder.IsComplete()) {
        LogPrintf("VaultMetadata::RebuildBuilder: Finalized builder invalid for contract %s\n",
                  contract_id.ToString());
        return TaprootBuilder{};
    }

    return builder;
}

// ============================================================================
// VaultRegistry Implementation
// ============================================================================

bool VaultRegistry::RegisterVault(const VaultMetadata& metadata)
{
    LOCK(cs_registry);

    // Validate before registration
    if (!metadata.Validate()) {
        LogPrintf("VaultRegistry::RegisterVault: Validation failed\n");
        return false;
    }

    // Get output key and scriptPubKey
    XOnlyPubKey output_key = metadata.GetOutputKey();
    CScript script_pubkey = metadata.GetScriptPubKey();

    // Check for duplicate registration
    if (m_metadata_by_outkey.find(output_key) != m_metadata_by_outkey.end()) {
        LogPrintf("VaultRegistry::RegisterVault: Vault already registered (output_key: %s)\n",
                  HexStr(output_key));
        return false;
    }

    // Register in all indices
    m_metadata_by_outkey[output_key] = metadata;
    m_outkey_by_script[script_pubkey] = output_key;
    m_outkeys_by_contract.insert({metadata.contract_id, output_key});

    LogPrintf("VaultRegistry::RegisterVault: Registered vault for contract %s (role: %s, output_key: %s)\n",
              metadata.contract_id.ToString(),
              VaultRoleToString(metadata.role),
              HexStr(output_key));

    return true;
}

std::optional<VaultMetadata> VaultRegistry::GetVaultByOutputKey(const XOnlyPubKey& output_key) const
{
    LOCK(cs_registry);

    auto it = m_metadata_by_outkey.find(output_key);
    if (it == m_metadata_by_outkey.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::optional<VaultMetadata> VaultRegistry::GetVaultByScript(const CScript& covenant_spk) const
{
    LOCK(cs_registry);

    // Lookup output key via secondary index
    auto it = m_outkey_by_script.find(covenant_spk);
    if (it == m_outkey_by_script.end()) {
        return std::nullopt;
    }

    const XOnlyPubKey& output_key = it->second;

    // Lookup metadata via primary index
    return GetVaultByOutputKey(output_key);
}

std::vector<VaultMetadata> VaultRegistry::GetContractVaults(const uint256& contract_id) const
{
    LOCK(cs_registry);

    std::vector<VaultMetadata> vaults;

    // Find all output keys for this contract
    auto range = m_outkeys_by_contract.equal_range(contract_id);
    for (auto it = range.first; it != range.second; ++it) {
        const XOnlyPubKey& output_key = it->second;

        auto meta_it = m_metadata_by_outkey.find(output_key);
        if (meta_it != m_metadata_by_outkey.end()) {
            vaults.push_back(meta_it->second);
        }
    }

    return vaults;
}

bool VaultRegistry::IsRegistered(const XOnlyPubKey& output_key) const
{
    LOCK(cs_registry);
    return m_metadata_by_outkey.find(output_key) != m_metadata_by_outkey.end();
}

bool VaultRegistry::IsRegistered(const CScript& covenant_spk) const
{
    LOCK(cs_registry);
    return m_outkey_by_script.find(covenant_spk) != m_outkey_by_script.end();
}

bool VaultRegistry::ValidateVault(const XOnlyPubKey& output_key) const
{
    LOCK(cs_registry);

    auto it = m_metadata_by_outkey.find(output_key);
    if (it == m_metadata_by_outkey.end()) {
        return false;
    }

    return it->second.Validate();
}

bool VaultRegistry::CacheXOnlyKey(const XOnlyPubKey& xonly, const CKey& key) const
{
    LOCK(cs_registry);

    // Validate key is correct for xonly pubkey
    CPubKey full_pubkey = key.GetPubKey();
    if (!full_pubkey.IsValid()) {
        return false;
    }

    XOnlyPubKey derived_xonly(full_pubkey);
    if (derived_xonly != xonly) {
        LogPrintf("VaultRegistry::CacheXOnlyKey: Key mismatch (expected: %s, got: %s)\n",
                  HexStr(xonly), HexStr(derived_xonly));
        return false;
    }

    m_xonly_key_cache[xonly] = key;
    return true;
}

std::optional<CKey> VaultRegistry::GetKeyByXOnly(const XOnlyPubKey& xonly) const
{
    LOCK(cs_registry);

    auto it = m_xonly_key_cache.find(xonly);
    if (it == m_xonly_key_cache.end()) {
        return std::nullopt;
    }

    return it->second;
}

bool VaultRegistry::Load(WalletBatch& batch)
{
    LOCK(cs_registry);

    // Clear existing data
    m_metadata_by_outkey.clear();
    m_outkey_by_script.clear();
    m_outkeys_by_contract.clear();
    m_xonly_key_cache.clear();

    // Note: Actual loading happens per-vault via RegisterVault calls
    // This method is primarily for initializing the registry state
    // Individual vaults are loaded when descriptors are loaded

    LogPrintf("VaultRegistry::Load: Registry initialized\n");
    return true;
}

bool VaultRegistry::Store(WalletBatch& batch) const
{
    LOCK(cs_registry);

    // Store all vault metadata to DB
    size_t stored = 0;
    for (const auto& [output_key, metadata] : m_metadata_by_outkey) {
        CScript script_pubkey = metadata.GetScriptPubKey();
        if (batch.WriteVaultMetadata(script_pubkey, metadata)) {
            ++stored;
        } else {
            LogPrintf("VaultRegistry::Store: Failed to write vault %s\n", HexStr(output_key));
            return false;
        }
    }

    LogPrintf("VaultRegistry::Store: Stored %zu vaults to DB\n", stored);
    return true;
}

size_t VaultRegistry::PruneInvalidVaults()
{
    LOCK(cs_registry);

    size_t pruned = 0;
    std::vector<XOnlyPubKey> invalid_keys;

    // Find all invalid vaults
    for (const auto& [output_key, metadata] : m_metadata_by_outkey) {
        if (!metadata.Validate()) {
            invalid_keys.push_back(output_key);
        }
    }

    // Remove from all indices
    for (const XOnlyPubKey& output_key : invalid_keys) {
        auto it = m_metadata_by_outkey.find(output_key);
        if (it != m_metadata_by_outkey.end()) {
            const VaultMetadata& metadata = it->second;

            // Remove from secondary index
            CScript script_pubkey = metadata.GetScriptPubKey();
            m_outkey_by_script.erase(script_pubkey);

            // Remove from tertiary index
            auto range = m_outkeys_by_contract.equal_range(metadata.contract_id);
            for (auto contract_it = range.first; contract_it != range.second; ) {
                if (contract_it->second == output_key) {
                    contract_it = m_outkeys_by_contract.erase(contract_it);
                } else {
                    ++contract_it;
                }
            }

            // Remove from primary index
            m_metadata_by_outkey.erase(it);
            ++pruned;
        }
    }

    if (pruned > 0) {
        LogPrintf("VaultRegistry::PruneInvalidVaults: Pruned %zu invalid vaults\n", pruned);
    }

    return pruned;
}

size_t VaultRegistry::Size() const
{
    LOCK(cs_registry);
    return m_metadata_by_outkey.size();
}

void VaultRegistry::Clear()
{
    LOCK(cs_registry);

    m_metadata_by_outkey.clear();
    m_outkey_by_script.clear();
    m_outkeys_by_contract.clear();
    m_xonly_key_cache.clear();

    LogPrintf("VaultRegistry::Clear: Cleared all vaults\n");
}

} // namespace wallet
