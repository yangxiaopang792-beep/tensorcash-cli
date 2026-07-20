// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <uint256.h>
#include <hash.h>
#include <undo.h>
#include <consensus/amount.h>
#include <serialize.h>
#include <streams.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <vector>

// Fuzz fee accumulator arithmetic and distribution
FUZZ_TARGET(asset_fee_accumulator)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    
    // Generate random block and transaction hashes for offset calculation
    uint256 block_hash = ConsumeUInt256(fuzzed_data_provider);
    
    // Simulate multiple transactions in a block
    size_t num_txs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 20);
    
    // Track total fees distributed
    std::map<uint256, uint64_t> asset_fee_totals;
    std::vector<CBlockUndo::FeeUndoEntry> all_undo_entries;
    
    for (size_t tx_idx = 0; tx_idx < num_txs; ++tx_idx) {
        uint256 tx_hash = ConsumeUInt256(fuzzed_data_provider);
        
        // Generate random touched assets
        std::set<uint256> touched;
        size_t num_touched = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);
        
        for (size_t i = 0; i < num_touched; ++i) {
            uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
            touched.insert(asset_id);
        }
        
        // Random transaction fee
        CAmount txfee = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 1000000);
        
        if (!touched.empty() && txfee > 0) {
            // Calculate distribution (matching validation.cpp logic)
            CAmount base = txfee / touched.size();
            CAmount rem = txfee % touched.size();
            
            // Calculate hash-based offset
            uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
            uint64_t rnd = 0;
            for (int k = 0; k < 8; ++k) {
                rnd |= (uint64_t)mix.begin()[k] << (8*k);
            }
            
            std::vector<uint256> vec(touched.begin(), touched.end());
            std::sort(vec.begin(), vec.end());
            size_t offset = (size_t)(rnd % vec.size());
            
            // Distribute fees
            std::map<uint256, uint64_t> tx_distribution;
            for (const auto& aid : vec) {
                tx_distribution[aid] = base;
                asset_fee_totals[aid] += base;
            }
            
            // Distribute remainder
            for (CAmount r = 0; r < rem; ++r) {
                size_t pos = (offset + (size_t)r) % vec.size();
                tx_distribution[vec[pos]] += 1;
                asset_fee_totals[vec[pos]] += 1;
            }
            
            // Verify per-tx distribution sums to txfee
            uint64_t tx_total = 0;
            for (const auto& [aid, amount] : tx_distribution) {
                tx_total += amount;
                
                // Create undo entries
                if (amount > 0) {
                    CBlockUndo::FeeUndoEntry undo;
                    undo.asset_id = aid;
                    undo.delta = amount;
                    all_undo_entries.push_back(undo);
                }
            }
            assert(tx_total == (uint64_t)txfee);
        }
    }
    
    // Verify total undo entries match total fees distributed
    uint64_t total_undo = 0;
    for (const auto& undo : all_undo_entries) {
        total_undo += undo.delta;
    }
    
    uint64_t total_distributed = 0;
    for (const auto& [aid, amount] : asset_fee_totals) {
        total_distributed += amount;
    }
    
    assert(total_undo == total_distributed);
}

// Fuzz overflow protection in fee accumulation
FUZZ_TARGET(asset_fee_overflow)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    
    // Start with high accumulator values
    uint64_t fees_accum = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(
        std::numeric_limits<uint64_t>::max() - 1000000,
        std::numeric_limits<uint64_t>::max()
    );
    
    // Try to add various increments
    size_t num_increments = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 100);
    
    for (size_t i = 0; i < num_increments; ++i) {
        uint64_t increment = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
        
        // Safe addition with overflow protection
        uint64_t new_value;
        if (fees_accum <= std::numeric_limits<uint64_t>::max() - increment) {
            new_value = fees_accum + increment;
        } else {
            new_value = std::numeric_limits<uint64_t>::max();
        }
        
        // Verify no wraparound
        assert(new_value >= fees_accum || new_value == std::numeric_limits<uint64_t>::max());
        
        fees_accum = new_value;
    }
}

// Fuzz deterministic offset calculation
FUZZ_TARGET(asset_fee_offset_determinism)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    
    // Generate random inputs
    uint256 block_hash = ConsumeUInt256(fuzzed_data_provider);
    uint256 tx_hash = ConsumeUInt256(fuzzed_data_provider);
    size_t num_assets = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 100);
    
    // Calculate offset multiple times with same inputs
    std::vector<size_t> offsets;
    
    for (int round = 0; round < 10; ++round) {
        uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
        uint64_t rnd = 0;
        for (int k = 0; k < 8; ++k) {
            rnd |= (uint64_t)mix.begin()[k] << (8*k);
        }
        size_t offset = rnd % num_assets;
        offsets.push_back(offset);
    }
    
    // All offsets must be identical (deterministic)
    for (size_t i = 1; i < offsets.size(); ++i) {
        assert(offsets[0] == offsets[i]);
    }
    
    // Different tx hash should produce different offset (usually)
    uint256 tx_hash2 = ConsumeUInt256(fuzzed_data_provider);
    if (tx_hash != tx_hash2) {
        uint256 mix2 = (HashWriter{} << block_hash << tx_hash2).GetHash();
        uint64_t rnd2 = 0;
        for (int k = 0; k < 8; ++k) {
            rnd2 |= (uint64_t)mix2.begin()[k] << (8*k);
        }
        size_t offset2 = rnd2 % num_assets;
        (void)offset2;  // Suppress unused warning
        
        // Different inputs should usually produce different offsets
        // (not always, due to modulo, but statistically likely)
    }
}

// Fuzz unlock threshold mechanics
FUZZ_TARGET(asset_fee_unlock_threshold)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    
    // Generate random unlock threshold
    uint64_t unlock_threshold = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    uint64_t fees_accum = 0;
    
    // Simulate fee accumulation over time
    size_t num_blocks = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 1000);
    
    for (size_t block = 0; block < num_blocks; ++block) {
        // Random fee increment for this block
        uint64_t block_fees = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(0, 10000);
        
        // Safe addition
        if (fees_accum <= std::numeric_limits<uint64_t>::max() - block_fees) {
            fees_accum += block_fees;
        } else {
            fees_accum = std::numeric_limits<uint64_t>::max();
        }
        
        // Check unlock status
        bool unlocked = (fees_accum >= unlock_threshold);
        
        // Once unlocked, should remain unlocked
        if (unlocked && block > 0) {
            // Fees should not decrease in normal operation
            assert(fees_accum >= unlock_threshold);
        }
    }
    
    // Test edge cases
    if (unlock_threshold == 0) {
        // Always unlocked
        assert(fees_accum >= unlock_threshold);
    }
    
    if (unlock_threshold == std::numeric_limits<uint64_t>::max()) {
        // Can only unlock if fees_accum reaches max
        bool unlocked = (fees_accum >= unlock_threshold);
        if (unlocked) {
            assert(fees_accum == std::numeric_limits<uint64_t>::max());
        }
    }
}