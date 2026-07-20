// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSETS_REGISTRY_H
#define BITCOIN_ASSETS_REGISTRY_H

#include <serialize.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <deque>

// Maximum number of historical compliance roots to retain in ring buffer
// Sized to cover worst-case rotation frequency relative to max_root_age
// (e.g., daily rotations over 10-day window = 10 entries; 32 provides 3x safety margin)
static constexpr size_t MAX_ROOT_HISTORY = 32;

// Maximum number of governance rotation snapshots to retain
// Provides full audit trail of policy changes (quorum, cap, ICU commits)
// Capped at 100 to bound memory/disk usage
static constexpr size_t MAX_ROTATION_HISTORY = 100;

// Historical compliance root entry for ring buffer storage
// Tracks past commitments to support proofs generated before rotation
struct ComplianceRootHistory {
    uint256 root_commit;       // Packed root‖height (28 bytes root + 4 bytes BE height)
    int activation_height{0};  // Block height when this root became active
    uint256 txid;              // Transaction that committed this root

    SERIALIZE_METHODS(ComplianceRootHistory, obj) {
        READWRITE(obj.root_commit);
        READWRITE(obj.activation_height);
        READWRITE(obj.txid);
    }
};

// Governance rotation snapshot for audit trail
// Captures the state of an IssuerReg before a rotation overwrites it
// Enables chronological history of policy changes and ICU text evolution
struct IssuerRegSnapshot {
    uint256 icu_ctxt_commit;      // ICU ciphertext commitment (key for historical payload lookup)
    uint256 icu_plain_commit;     // ICU plaintext commitment (optional, for UX)
    uint16_t policy_quorum_bps;   // Governance quorum at this epoch
    uint64_t issuance_cap_units;  // Issuance cap at this epoch
    uint8_t policy_epoch;         // Epoch number for this snapshot
    int32_t block_height;         // Block height when rotation was confirmed
    uint256 rotation_txid;        // Transaction that rotated to the NEXT state
    uint32_t timestamp;           // Block timestamp when rotation occurred

    SERIALIZE_METHODS(IssuerRegSnapshot, obj) {
        READWRITE(obj.icu_ctxt_commit);
        READWRITE(obj.icu_plain_commit);
        READWRITE(obj.policy_quorum_bps);
        READWRITE(obj.issuance_cap_units);
        READWRITE(obj.policy_epoch);
        READWRITE(obj.block_height);
        READWRITE(obj.rotation_txid);
        READWRITE(obj.timestamp);
    }
};

// Scalar-feed publication record stored in LevelDB (prefix 'S'), keyed by
// (asset_id, feed_id, scalar_epoch). One immutable point per published epoch
// (CFD_GENERALISATION.md §3.2). The mandatory head record (prefix 's') maps
// (asset_id, feed_id) -> last_epoch and is a plain uint64 — no struct needed.
struct ScalarRecord {
    uint256  scalar;                 // raw 256-bit value, interpreted per scalar_format_id
    int32_t  publication_height{0};  // block height that confirmed it (for O(1) burial)
    uint16_t scalar_format_id{0};    // scalar ENCODING (see assets::IsKnownScalarFormat)

    SERIALIZE_METHODS(ScalarRecord, obj) {
        READWRITE(obj.scalar);
        READWRITE(obj.publication_height);
        READWRITE(obj.scalar_format_id);
    }
};

// Asset Registry Entry stored in LevelDB (prefix 'R')
struct AssetRegistryEntry {
    uint32_t policy_bits{0};
    uint16_t allowed_spk_families{0};
    COutPoint icu_outpoint; // current Issuer Credential UTXO for this asset
    uint64_t unlock_fees_sats{std::numeric_limits<uint64_t>::max()}; // default: never unlock unless set
    uint64_t fees_accum_sats{0};
    uint64_t rotation_min_sats{0}; // tracks minimum rotation value
    // Optional ticker (empty means none)
    std::string ticker;
    // Optional decimals; 255 means not set
    uint8_t decimals{255};

    // Optional ZK metadata persisted when KYC flows are enabled
    bool has_kyc{false};
    uint256 zk_vk_commitment;
    uint32_t max_root_age{0};
    uint32_t tfr_flags{0};

    // Compliance root commitment (ZK Whitelist Hardening)
    // Binds every KYC asset spend to an issuer-controlled compliance root committed on-chain
    // Format: 28 bytes Merkle root || 4 bytes big-endian capture height
    uint256 compliance_root_commit;  // Active commitment (zero = not set)
    std::deque<ComplianceRootHistory> compliance_root_history;  // Ring buffer of recent commitments

    // Governance rotation history (audit trail)
    // Chronological snapshots of prior IssuerReg states before each rotation
    // Ordered by policy_epoch (append-only), capped at MAX_ROTATION_HISTORY
    std::deque<IssuerRegSnapshot> rotation_history;

    // Supply tracking (for quorum calculation and cap enforcement)
    uint64_t issued_total{0};  // cumulative minted units
    uint64_t burned_total{0};  // cumulative burned units

    // ICU / Governance metadata (v2)
    uint32_t icu_flags{0};               // structural flags (e.g., WRAP_REQUIRED)
    uint8_t icu_visibility{0};           // 0/1, mutable via quorum
    uint8_t icu_version{0};              // ICU_VERSION_V1 = 1
    uint16_t policy_quorum_bps{0};       // 0 => immutable after issuance (except 75% override)
    uint64_t issuance_cap_units{0};      // 0 => unlimited; monotonic non-decreasing
    uint64_t unlock_fees_base{0};        // base unlock threshold; rotations bump for ICU changes
    uint256 icu_ctxt_commit;             // SHA256(raw ICU payload stored on chain)
    uint256 icu_plain_commit;            // optional UX binding (zero => unused)
    std::array<unsigned char, 16> kdf_salt{}; // optional; zero => none
    uint256 core_policy_commit;          // SHA256 over immutable core fields
    uint8_t policy_epoch{0};             // wallet advisory version counter

    // --- v5: reusable / delegated KYC (see REUSABLE_KYC.md) ---
    // Delegation pointer. Null = self (this asset supplies its own identity
    // material). Non-null = follow that asset's VK/root/history (one hop only,
    // enforced at spend time). Asset-scoped semantics (asset_id, tfr_flags)
    // always stay with THIS asset, never the source.
    uint256 compliance_delegate_asset_id;
    // Height at which the ACTIVE compliance root became active. Explicit (not
    // derived from history) because the "root unchanged" rotation branch pushes
    // no history entry. Used by the delegated-asset staleness heartbeat.
    int32_t active_root_activation_height{0};
    // Per-history-entry VK commitment, PARALLEL to compliance_root_history
    // (entry i's root was committed under vk[i]). Enables rolling circuit
    // migration: a historical-root match is verified under its own VK rather
    // than the current one. Empty (legacy entry) => fall back to the active
    // zk_vk_commitment for historical matches.
    std::deque<uint256> compliance_root_history_vk;

    // Helper to check if unlocked
    bool IsUnlocked() const {
        return fees_accum_sats >= unlock_fees_sats;
    }

    // Get current minimum rotation value
    // Note: Dust threshold calculation should happen at the call site with proper context
    CAmount GetMinRotationValue() const {
        return rotation_min_sats;
    }

    SERIALIZE_METHODS(AssetRegistryEntry, obj) {
        // Core fields (always present in all versions)
        READWRITE(obj.policy_bits);
        READWRITE(obj.allowed_spk_families);
        READWRITE(obj.icu_outpoint);
        READWRITE(obj.unlock_fees_sats);
        READWRITE(obj.fees_accum_sats);
        READWRITE(obj.rotation_min_sats);
        READWRITE(LIMITED_STRING(obj.ticker, 32));
        READWRITE(obj.decimals);

        // Extended fields: Use exception-based detection for backward compatibility
        // On Write: always write all fields
        // On Read: try to read all fields; if we hit EOF, initialize remaining to defaults
        if constexpr (ser_action.ForRead()) {
            try {
                // KYC / ZK fields (v2)
                READWRITE(obj.has_kyc);
                READWRITE(obj.zk_vk_commitment);
                READWRITE(obj.max_root_age);
                READWRITE(obj.tfr_flags);

                // Compliance root fields (v3)
                READWRITE(obj.compliance_root_commit);
                READWRITE(obj.compliance_root_history);

                // Rotation history fields (v4)
                READWRITE(obj.rotation_history);

                // Supply tracking fields (v2)
                READWRITE(obj.issued_total);
                READWRITE(obj.burned_total);

                // ICU / Governance fields (v2)
                READWRITE(obj.icu_flags);
                READWRITE(obj.icu_visibility);
                READWRITE(obj.icu_version);
                READWRITE(obj.policy_quorum_bps);
                READWRITE(obj.issuance_cap_units);
                READWRITE(obj.unlock_fees_base);
                READWRITE(obj.icu_ctxt_commit);
                READWRITE(obj.icu_plain_commit);
                READWRITE(obj.kdf_salt);
                READWRITE(obj.core_policy_commit);
                READWRITE(obj.policy_epoch);

                // Reusable / delegated KYC fields (v5). NESTED best-effort read:
                // a v2-v4 entry ends at policy_epoch, so EOF here must default
                // ONLY the v5 fields and NOT propagate to the outer catch (which
                // would reset has_kyc/root/... and silently turn a KYC asset into
                // a non-KYC one). See REUSABLE_KYC.md §2.1.
                try {
                    READWRITE(obj.compliance_delegate_asset_id);
                    READWRITE(obj.active_root_activation_height);
                    READWRITE(obj.compliance_root_history_vk);
                } catch (const std::ios_base::failure&) {
                    obj.compliance_delegate_asset_id.SetNull();
                    obj.active_root_activation_height = 0;
                    obj.compliance_root_history_vk.clear();
                }
            } catch (const std::ios_base::failure&) {
                // Legacy entry detected (v1 or partial v2/v3) - initialize missing fields to defaults
                // This handles the case where we're reading older serialized data that doesn't
                // have all the fields. Default-initialize everything that failed to deserialize.
                obj.has_kyc = false;
                obj.zk_vk_commitment.SetNull();
                obj.max_root_age = 0;
                obj.tfr_flags = 0;
                obj.compliance_root_commit.SetNull();
                obj.compliance_root_history.clear();
                obj.rotation_history.clear();
                obj.issued_total = 0;
                obj.burned_total = 0;
                obj.icu_flags = 0;
                obj.icu_visibility = 0;
                obj.icu_version = 0;
                obj.policy_quorum_bps = 0;
                obj.issuance_cap_units = 0;
                obj.unlock_fees_base = 0;
                obj.icu_ctxt_commit.SetNull();
                obj.icu_plain_commit.SetNull();
                obj.kdf_salt.fill(0);
                obj.core_policy_commit.SetNull();
                obj.policy_epoch = 0;
                obj.compliance_delegate_asset_id.SetNull();
                obj.active_root_activation_height = 0;
                obj.compliance_root_history_vk.clear();
            }
        } else {
            // Write path: always write all fields unconditionally
            READWRITE(obj.has_kyc);
            READWRITE(obj.zk_vk_commitment);
            READWRITE(obj.max_root_age);
            READWRITE(obj.tfr_flags);
            READWRITE(obj.compliance_root_commit);
            READWRITE(obj.compliance_root_history);
            READWRITE(obj.rotation_history);
            READWRITE(obj.issued_total);
            READWRITE(obj.burned_total);
            READWRITE(obj.icu_flags);
            READWRITE(obj.icu_visibility);
            READWRITE(obj.icu_version);
            READWRITE(obj.policy_quorum_bps);
            READWRITE(obj.issuance_cap_units);
            READWRITE(obj.unlock_fees_base);
            READWRITE(obj.icu_ctxt_commit);
            READWRITE(obj.icu_plain_commit);
            READWRITE(obj.kdf_salt);
            READWRITE(obj.core_policy_commit);
            READWRITE(obj.policy_epoch);
            // Reusable / delegated KYC fields (v5) — always written last.
            READWRITE(obj.compliance_delegate_asset_id);
            READWRITE(obj.active_root_activation_height);
            READWRITE(obj.compliance_root_history_vk);
        }
    }
};

#endif // BITCOIN_ASSETS_REGISTRY_H
