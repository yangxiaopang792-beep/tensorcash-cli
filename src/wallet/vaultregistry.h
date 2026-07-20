// Copyright (c) 2024-present TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_VAULTREGISTRY_H
#define BITCOIN_WALLET_VAULTREGISTRY_H

#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace wallet {

class WalletBatch;

/**
 * VaultRole - Defines which party/role owns a vault and which leaves they can sign
 */
enum class VaultRole : uint8_t {
    REPO_BORROWER,    // Signs repay leaf
    REPO_LENDER,      // Signs default leaf
    FORWARD_LONG,     // Signs long timeout/delivery leaves (IM vault)
    FORWARD_SHORT,    // Signs short timeout/delivery leaves (IM vault)
    FORWARD_ESCROW_B, // Signers associated with B escrow tree
    FORWARD_ESCROW_A, // Signers associated with A escrow tree
    DIFFICULTY_LONG,  // Long-leg IM vault of a difficulty derivative (loses as difficulty falls)
    DIFFICULTY_SHORT  // Short-leg IM vault of a difficulty derivative (loses as difficulty rises)
};

std::string VaultRoleToString(VaultRole role);

/**
 * VaultLeafDescriptor - Metadata for a single leaf in a taproot vault tree
 */
struct VaultLeafDescriptor {
    std::vector<unsigned char> script;  // Raw leaf script bytes
    uint8_t leaf_version;               // Usually TAPROOT_LEAF_TAPSCRIPT (0xc0)
    //! X-only key that signs this leaf (32 bytes). An ALL-ZERO (null) key marks a COVENANT-ONLY
    //! leaf: signatureless and keeper-spendable (spent by revealing the committed leaf script, e.g.
    //! the difficulty-derivative unilateral settlement leaf). See IsCovenantOnly().
    XOnlyPubKey signing_key;
    std::string purpose;                // "repay", "default", "timeout", "delivery", "difficulty-settle", etc.
    std::optional<uint32_t> timelock;   // CLTV/CSV value if applicable

    /** A covenant-only leaf has no signing authority (null signing_key) and is spent by anyone
     *  (a keeper) revealing its committed script. Backward-compatible: it reuses the existing
     *  signing_key field as an all-zero sentinel, so the serialized format is unchanged. */
    bool IsCovenantOnly() const { return signing_key.IsNull(); }

    /** Validate descriptor fields */
    bool Validate() const;

    SERIALIZE_METHODS(VaultLeafDescriptor, obj) {
        READWRITE(obj.script, obj.leaf_version, obj.signing_key, obj.purpose);

        // Serialize optional timelock manually: bool flag + value if present
        bool has_timelock = obj.timelock.has_value();
        SER_WRITE(obj, ::Serialize(s, has_timelock));
        SER_READ(obj, ::Unserialize(s, has_timelock));

        if (has_timelock) {
            if constexpr (ser_action.ForRead()) {
                uint32_t value;
                ::Unserialize(s, value);
                obj.timelock = value;
            } else {
                ::Serialize(s, *obj.timelock);
            }
        } else {
            SER_READ(obj, obj.timelock = std::nullopt);
        }
    }
};

/**
 * VaultMetadata - Complete description of a taproot covenant vault
 *
 * This structure stores everything needed to:
 * 1. Sign any spending path (via spenddata)
 * 2. Validate the vault structure (via leaves)
 * 3. Determine signing authority (via role)
 *
 * Primary storage is TaprootSpendData (not TaprootBuilder) for stability.
 */
struct VaultMetadata {
    static constexpr uint32_t CURRENT_VERSION = 1;
    uint32_t version = CURRENT_VERSION;        // For future migrations

    // Persistent data (stored in DB)
    TaprootSpendData spenddata;                // Primary: internal key + merkle + scripts
    std::vector<VaultLeafDescriptor> leaves;   // Leaf metadata with signing info

    // Context
    uint256 contract_id;                       // Offer ID or contract ID
    VaultRole role;                            // Which party/role owns this vault

    // Derived (computed on load, not stored)
    mutable std::optional<XOnlyPubKey> cached_output_key;
    mutable std::optional<CScript> cached_scriptPubKey;

    /** Lazy accessor - compute output key from spenddata */
    XOnlyPubKey GetOutputKey() const;

    /** Lazy accessor - compute scriptPubKey from output key */
    CScript GetScriptPubKey() const;

    /** Validate internal consistency of vault metadata */
    bool Validate() const;

    /** Reconstruct a TaprootBuilder from spenddata (for legacy APIs) */
    TaprootBuilder RebuildBuilder() const;

    // Custom serialization because TaprootSpendData doesn't have SERIALIZE_METHODS
    template <typename Stream>
    void Serialize(Stream& s) const {
        // Serialize version
        ::Serialize(s, version);

        // Serialize TaprootSpendData fields manually
        ::Serialize(s, spenddata.internal_key);
        ::Serialize(s, spenddata.merkle_root);
        ::Serialize(s, spenddata.scripts);

        // Serialize the rest
        ::Serialize(s, leaves);
        ::Serialize(s, contract_id);

        // Serialize role as uint8_t (enum class underlying type)
        ::Serialize(s, static_cast<uint8_t>(role));
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        // Deserialize version
        ::Unserialize(s, version);

        // Deserialize TaprootSpendData fields manually
        ::Unserialize(s, spenddata.internal_key);
        ::Unserialize(s, spenddata.merkle_root);
        ::Unserialize(s, spenddata.scripts);

        // Deserialize the rest
        ::Unserialize(s, leaves);
        ::Unserialize(s, contract_id);

        // Deserialize role from uint8_t
        uint8_t role_value;
        ::Unserialize(s, role_value);
        role = static_cast<VaultRole>(role_value);

        // Clear caches
        cached_output_key.reset();
        cached_scriptPubKey.reset();
    }
};

/**
 * VaultBuilder - Factory for constructing VaultMetadata from TaprootBuilder
 *
 * This utility converts a TaprootBuilder + leaf metadata into a complete
 * VaultMetadata object suitable for registration in the VaultRegistry.
 */
class VaultBuilder {
public:
    /**
     * Build VaultMetadata from a TaprootBuilder + leaf descriptors
     *
     * @param builder      Completed TaprootBuilder with all leaves finalized
     * @param contract_id  Contract or offer ID
     * @param role         Which party/role this vault belongs to
     * @param leaf_metadata Descriptors for each leaf (script, signing_key, purpose)
     * @return VaultMetadata if valid, std::nullopt otherwise
     */
    static std::optional<VaultMetadata> Build(
        const TaprootBuilder& builder,
        const uint256& contract_id,
        VaultRole role,
        const std::vector<VaultLeafDescriptor>& leaf_metadata);

    /**
     * Create a VaultLeafDescriptor from components
     *
     * @param script      The leaf script (covenant script)
     * @param signing_key The x-only key that can sign this leaf
     * @param purpose     Human-readable purpose ("repay", "default", etc.)
     * @param timelock    Optional CLTV/CSV timelock value
     * @return Fully constructed VaultLeafDescriptor
     */
    static VaultLeafDescriptor CreateLeaf(
        const CScript& script,
        const XOnlyPubKey& signing_key,
        const std::string& purpose,
        std::optional<uint32_t> timelock = std::nullopt);
};

/**
 * VaultRegistry - Central registry for all covenant vaults in a wallet
 *
 * Index Strategy:
 * - PRIMARY: output_key → metadata (used by signing path)
 * - SECONDARY: covenant_script → output_key (used by RPC/solvability)
 * - TERTIARY: contract_id → output_keys (for querying all vaults in contract)
 *
 * The primary index uses output_key because that's what SignTaproot queries.
 */
class VaultRegistry {
private:
    mutable RecursiveMutex cs_registry;

    // PRIMARY INDEX: output key → metadata (signing path uses output key)
    std::map<XOnlyPubKey, VaultMetadata> m_metadata_by_outkey GUARDED_BY(cs_registry);

    // SECONDARY INDEX: covenant script → output key (for RPC/solvability lookups)
    std::map<CScript, XOnlyPubKey> m_outkey_by_script GUARDED_BY(cs_registry);

    // TERTIARY INDEX: contract_id → output keys (for querying all vaults in contract)
    std::multimap<uint256, XOnlyPubKey> m_outkeys_by_contract GUARDED_BY(cs_registry);

    // X-only key lookup shim (lazy cache)
    mutable std::map<XOnlyPubKey, CKey> m_xonly_key_cache GUARDED_BY(cs_registry);

public:
    /** Register a new vault (builds all indices) */
    bool RegisterVault(const VaultMetadata& metadata);

    /** Lookup by output key (primary, used by signing) */
    std::optional<VaultMetadata> GetVaultByOutputKey(const XOnlyPubKey& output_key) const;

    /** Lookup by script (secondary, used by RPC) */
    std::optional<VaultMetadata> GetVaultByScript(const CScript& covenant_spk) const;

    /** Lookup all vaults for a contract */
    std::vector<VaultMetadata> GetContractVaults(const uint256& contract_id) const;

    /** Check if vault is registered by output key */
    bool IsRegistered(const XOnlyPubKey& output_key) const;

    /** Check if vault is registered by script */
    bool IsRegistered(const CScript& covenant_spk) const;

    /** Validate a registered vault */
    bool ValidateVault(const XOnlyPubKey& output_key) const;

    /** Cache an x-only key mapping for signing (mutable cache in const method) */
    bool CacheXOnlyKey(const XOnlyPubKey& xonly, const CKey& key) const;

    /** Retrieve cached x-only key */
    std::optional<CKey> GetKeyByXOnly(const XOnlyPubKey& xonly) const;

    /** Load all vaults from wallet DB */
    bool Load(WalletBatch& batch);

    /** Store all vaults to wallet DB */
    bool Store(WalletBatch& batch) const;

    /** Remove vaults that fail validation (for migration/recovery) */
    size_t PruneInvalidVaults();

    /** Get count of registered vaults (for debugging) */
    size_t Size() const;

    /** Clear all vaults (for testing) */
    void Clear();
};

} // namespace wallet

#endif // BITCOIN_WALLET_VAULTREGISTRY_H
