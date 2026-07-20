// Copyright (c) 2024-present TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_VAULT_SIGNING_H
#define BITCOIN_WALLET_VAULT_SIGNING_H

#include <psbt.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <wallet/vaultregistry.h>

#include <optional>
#include <string>
#include <vector>

namespace wallet {

/**
 * VaultSigningIntent - Explicit specification of which vault leaf to sign
 *
 * This structure embeds the exact signing intent into PSBTs, eliminating
 * ambiguity when multiple leaves share the same signing key (e.g., cooperative
 * vs timeout paths). The signer enforces this intent and fails hard if the
 * specified leaf cannot be resolved or doesn't match the vault metadata.
 *
 * Design:
 * - Stored as a BIP174 proprietary PSBT field (prefix "fs", per-input)
 * - Contains minimal data: purpose + tapleaf hash + control block
 * - Script bytes are NOT included (reconstructed from metadata) to keep PSBT size sane
 * - Signer validates intent against VaultMetadata and fails if mismatched
 */
struct VaultSigningIntent {
    std::string leaf_purpose;                 // "cooperative", "timeout", "self_delivery", "repo_settlement", etc.
    uint256 tapleaf_hash;                     // Hash of the leaf to sign (OP_TAPLEAF_VERSION || script)
    std::vector<unsigned char> control_block; // Control block proving leaf membership

    // Optional: fingerprints of required signers (for multi-party validation)
    std::vector<uint32_t> signer_fingerprints;

    // Optional: timelock height/value (for validation before signing)
    std::optional<uint32_t> timelock_value;

    /** Validate intent structure */
    bool Validate() const;

    /** Equality comparison */
    bool operator==(const VaultSigningIntent& other) const;

    SERIALIZE_METHODS(VaultSigningIntent, obj) {
        READWRITE(obj.leaf_purpose, obj.tapleaf_hash, obj.control_block);

        // Serialize optional signer fingerprints
        READWRITE(obj.signer_fingerprints);

        // Serialize optional timelock manually
        bool has_timelock = obj.timelock_value.has_value();
        READWRITE(has_timelock);

        if (has_timelock) {
            if constexpr (ser_action.ForRead()) {
                uint32_t value;
                READWRITE(value);
                obj.timelock_value = value;
            } else {
                READWRITE(*obj.timelock_value);
            }
        } else {
            SER_READ(obj, obj.timelock_value = std::nullopt);
        }
    }
};

/**
 * PSBT proprietary key structure for vault intent
 *
 * Format (BIP174 proprietary):
 *   key = 0xFC || <compact size> || "fs" || <subtype> || <keydata>
 *   value = <serialized VaultSigningIntent>
 *
 * Identifier: "fs" (Fair-Sign system)
 * Subtype: VAULT_INTENT (0x01)
 * Keydata: input index (for validation, though PSBT context provides this)
 */
static constexpr const char* PSBT_FS_IDENTIFIER = "fs";
static constexpr uint64_t PSBT_FS_VAULT_INTENT_SUBTYPE = 0x01;
static constexpr uint64_t PSBT_FS_INPUT_TYPE_SUBTYPE = 0x02;  // For optional input type tagging

/**
 * Input type tags for debugging/validation (optional metadata)
 */
enum class VaultInputType : uint8_t {
    UNKNOWN = 0,
    FORWARD_VAULT_COOPERATIVE,
    FORWARD_VAULT_TIMEOUT,
    FORWARD_VAULT_SELF_DELIVERY,
    REPO_VAULT_SETTLEMENT,
    REPO_VAULT_TIMEOUT,
    FUNDING_INPUT,
};

std::string VaultInputTypeToString(VaultInputType type);

/**
 * PSBT Vault Intent Helpers
 */

/**
 * Embed a VaultSigningIntent into a PSBT input
 *
 * @param input      PSBT input to modify
 * @param intent     Vault signing intent to embed
 * @return true if successfully embedded, false on error
 */
bool EmbedVaultIntent(PSBTInput& input, const VaultSigningIntent& intent);

/**
 * Extract VaultSigningIntent from a PSBT input
 *
 * @param input      PSBT input to read from
 * @return Intent if present and valid, std::nullopt otherwise
 */
std::optional<VaultSigningIntent> ExtractVaultIntent(const PSBTInput& input);

/**
 * Embed optional input type tag into PSBT input (for debugging)
 *
 * @param input      PSBT input to modify
 * @param type       Input type tag
 * @return true if successfully embedded
 */
bool EmbedInputType(PSBTInput& input, VaultInputType type);

/**
 * Extract input type tag from PSBT input
 *
 * @param input      PSBT input to read from
 * @return Type if present, VaultInputType::UNKNOWN otherwise
 */
VaultInputType ExtractInputType(const PSBTInput& input);

/**
 * Vault Intent Validation
 */

/**
 * Validate that a VaultSigningIntent matches the vault metadata
 *
 * Checks:
 * 1. Leaf with matching tapleaf_hash exists in metadata
 * 2. Leaf purpose matches intent purpose
 * 3. Control block is valid for the leaf
 * 4. If timelock specified, it's consistent with leaf metadata
 *
 * @param metadata   Vault metadata from registry
 * @param intent     Intent extracted from PSBT
 * @param error      Output error message if validation fails
 * @return true if valid, false otherwise (with error set)
 */
bool ValidateVaultIntent(const VaultMetadata& metadata,
                        const VaultSigningIntent& intent,
                        std::string& error);

/**
 * Select the leaf from metadata matching the intent
 *
 * @param metadata   Vault metadata
 * @param intent     Vault signing intent
 * @return Leaf descriptor if found and valid, std::nullopt otherwise
 */
std::optional<VaultLeafDescriptor> SelectLeafByIntent(
    const VaultMetadata& metadata,
    const VaultSigningIntent& intent);

/**
 * Validate timelock requirements before signing
 *
 * For leaves with timelocks (CLTV/CSV), verify that:
 * - Current chain height satisfies CLTV requirements
 * - Transaction structure satisfies CSV requirements
 *
 * @param leaf       Leaf descriptor with optional timelock
 * @param chain_tip  Current blockchain tip height
 * @param error      Output error message if validation fails
 * @return true if timelock satisfied or not required, false otherwise
 */
bool ValidateTimelock(const VaultLeafDescriptor& leaf,
                     int chain_tip,
                     std::string& error);

/**
 * Builder Helpers - Create VaultSigningIntent from VaultMetadata
 */

/**
 * Create a VaultSigningIntent for a cooperative leaf
 *
 * @param metadata   Vault metadata containing cooperative leaf
 * @return Intent for cooperative signing, or std::nullopt if no coop leaf
 */
std::optional<VaultSigningIntent> CreateCooperativeIntent(const VaultMetadata& metadata);

/**
 * Create a VaultSigningIntent for a timeout/fallback leaf
 *
 * @param metadata   Vault metadata
 * @param purpose    Purpose string ("timeout", "self_delivery", etc.)
 * @return Intent for timeout leaf, or std::nullopt if not found
 */
std::optional<VaultSigningIntent> CreateTimeoutIntent(
    const VaultMetadata& metadata,
    const std::string& purpose);

/**
 * Create a VaultSigningIntent from a specific leaf descriptor
 *
 * @param leaf       Leaf descriptor from metadata
 * @param spenddata  Taproot spend data to compute control block
 * @return Intent for the specified leaf
 */
VaultSigningIntent CreateIntentFromLeaf(
    const VaultLeafDescriptor& leaf,
    const TaprootSpendData& spenddata);

} // namespace wallet

#endif // BITCOIN_WALLET_VAULT_SIGNING_H
