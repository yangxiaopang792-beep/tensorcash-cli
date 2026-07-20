// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <assets/registry.h>
#include <assets/asset.h>
#include <primitives/transaction.h>
#include <undo.h>
#include <uint256.h>
#include <util/transaction_identifier.h>

#include <map>
#include <vector>
#include <algorithm>

// In-memory registry for fuzzing
class FuzzAssetRegistry {
public:  // Make members public for test access
    std::map<uint256, AssetRegistryEntry> registry;
    std::vector<CBlockUndo::RegUndoEntry> undo_stack;
    bool HasAsset(const uint256& asset_id) const {
        return registry.find(asset_id) != registry.end();
    }
    
    bool GetEntry(const uint256& asset_id, AssetRegistryEntry& entry) const {
        auto it = registry.find(asset_id);
        if (it != registry.end()) {
            entry = it->second;
            return true;
        }
        return false;
    }
    
    void WriteEntry(const uint256& asset_id, const AssetRegistryEntry& entry) {
        // Save undo information
        CBlockUndo::RegUndoEntry undo;
        undo.asset_id = asset_id;
        
        auto it = registry.find(asset_id);
        if (it != registry.end()) {
            undo.had_prev = true;
            undo.prev = it->second;
        } else {
            undo.had_prev = false;
        }
        undo_stack.push_back(undo);
        
        // Write new entry
        registry[asset_id] = entry;
    }
    
    void EraseEntry(const uint256& asset_id) {
        // Save undo information
        CBlockUndo::RegUndoEntry undo;
        undo.asset_id = asset_id;
        
        auto it = registry.find(asset_id);
        if (it != registry.end()) {
            undo.had_prev = true;
            undo.prev = it->second;
            registry.erase(it);
        } else {
            undo.had_prev = false;
        }
        undo_stack.push_back(undo);
    }
    
    void ApplyUndo(const CBlockUndo::RegUndoEntry& undo) {
        if (undo.had_prev) {
            registry[undo.asset_id] = undo.prev;
        } else {
            registry.erase(undo.asset_id);
        }
    }
    
    size_t Size() const { return registry.size(); }
    
    void Clear() { 
        registry.clear(); 
        undo_stack.clear();
    }
};

// Fuzz registry state transitions
FUZZ_TARGET(asset_registry_state)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FuzzAssetRegistry registry;
    
    // Perform random operations
    size_t num_operations = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 100);
    
    for (size_t op_idx = 0; op_idx < num_operations; ++op_idx) {
        uint8_t operation = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 5);
        
        switch (operation) {
            case 0: { // Register new asset
                uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                AssetRegistryEntry entry;
                entry.policy_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                entry.allowed_spk_families = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
                entry.icu_outpoint.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
                entry.icu_outpoint.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                entry.unlock_fees_sats = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
                entry.fees_accum_sats = 0;
                
                registry.WriteEntry(asset_id, entry);
                
                // Verify write succeeded
                AssetRegistryEntry check;
                assert(registry.GetEntry(asset_id, check));
                assert(check.policy_bits == entry.policy_bits);
                break;
            }
            
            case 1: { // Update existing asset (ICU rotation)
                if (registry.Size() > 0) {
                    uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                    AssetRegistryEntry entry;
                    
                    if (registry.GetEntry(asset_id, entry)) {
                        // Update ICU
                        COutPoint new_icu;
                        new_icu.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
                        new_icu.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                        
                        entry.icu_outpoint = new_icu;
                        registry.WriteEntry(asset_id, entry);
                        
                        // Verify update
                        AssetRegistryEntry check;
                        assert(registry.GetEntry(asset_id, check));
                        assert(check.icu_outpoint == new_icu);
                    }
                }
                break;
            }
            
            case 2: { // Accumulate fees
                if (registry.Size() > 0) {
                    uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                    AssetRegistryEntry entry;
                    
                    if (registry.GetEntry(asset_id, entry)) {
                        uint64_t fee_increment = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
                        
                        // Safe addition with overflow check
                        if (entry.fees_accum_sats <= std::numeric_limits<uint64_t>::max() - fee_increment) {
                            entry.fees_accum_sats += fee_increment;
                        } else {
                            entry.fees_accum_sats = std::numeric_limits<uint64_t>::max();
                        }
                        
                        registry.WriteEntry(asset_id, entry);
                        
                        // Check if unlocked
                        bool unlocked = (entry.fees_accum_sats >= entry.unlock_fees_sats);
                        (void)unlocked; // Suppress unused warning
                    }
                }
                break;
            }
            
            case 3: { // Erase asset (after unlock)
                if (registry.Size() > 0) {
                    uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                    AssetRegistryEntry entry;
                    
                    if (registry.GetEntry(asset_id, entry)) {
                        // Check if unlocked before erasing
                        bool can_erase = (entry.fees_accum_sats >= entry.unlock_fees_sats);
                        
                        if (can_erase || fuzzed_data_provider.ConsumeBool()) {
                            registry.EraseEntry(asset_id);
                            
                            // Verify erasure
                            assert(!registry.GetEntry(asset_id, entry));
                        }
                    }
                }
                break;
            }
            
            case 4: { // Test undo operation
                if (!registry.undo_stack.empty() && fuzzed_data_provider.ConsumeBool()) {
                    // Apply last undo
                    auto undo = registry.undo_stack.back();
                    registry.undo_stack.pop_back();
                    registry.ApplyUndo(undo);
                }
                break;
            }
            
            case 5: { // Batch operations (simulate block processing)
                size_t batch_size = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);
                std::vector<std::pair<uint256, AssetRegistryEntry>> updates;
                
                for (size_t i = 0; i < batch_size; ++i) {
                    uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                    AssetRegistryEntry entry;
                    entry.policy_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                    entry.allowed_spk_families = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
                    entry.icu_outpoint.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
                    entry.icu_outpoint.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                    
                    updates.push_back({asset_id, entry});
                }
                
                // Apply all updates
                for (const auto& [asset_id, entry] : updates) {
                    registry.WriteEntry(asset_id, entry);
                }
                break;
            }
        }
    }
    
    // Test final state consistency
    for (const auto& undo : registry.undo_stack) {
        // Each undo entry should be valid
        assert(!undo.asset_id.IsNull());
    }
}

// Fuzz registry collision handling
FUZZ_TARGET(asset_registry_collisions)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FuzzAssetRegistry registry;
    
    // Generate a small set of asset IDs to increase collision probability
    std::vector<uint256> asset_ids;
    size_t num_assets = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(2, 10);
    
    for (size_t i = 0; i < num_assets; ++i) {
        uint256 id = ConsumeUInt256(fuzzed_data_provider);
        asset_ids.push_back(id);
    }
    
    // Perform operations with high collision probability
    size_t num_operations = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(10, 100);
    
    for (size_t op_idx = 0; op_idx < num_operations; ++op_idx) {
        // Pick random asset from limited set
        uint256 asset_id = asset_ids[fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, asset_ids.size() - 1)];
        
        AssetRegistryEntry entry;
        bool exists = registry.GetEntry(asset_id, entry);
        
        if (!exists || fuzzed_data_provider.ConsumeBool()) {
            // Register or re-register
            entry.policy_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            entry.allowed_spk_families = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
            entry.icu_outpoint.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
            entry.icu_outpoint.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            
            // Test duplicate registration protection
            if (exists) {
                // Would need to spend current ICU in real validation
                // Here we just test the registry mechanics
            }
            
            registry.WriteEntry(asset_id, entry);
        }
    }
    
    // Verify final state
    assert(registry.Size() <= num_assets);
}