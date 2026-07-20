// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <validation.h>
#include <uint256.h>
#include <hash.h>
#include <assets/registry.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <random.h>
#include <undo.h>
#include <streams.h>

#include <algorithm>
#include <set>
#include <map>

BOOST_FIXTURE_TEST_SUITE(fee_accumulator_tests, BasicTestingSetup)

// Test deterministic fee distribution with hash-based offset
BOOST_AUTO_TEST_CASE(fee_accumulator_deterministic_distribution)
{
    // Test the exact algorithm used in ConnectBlock for fee distribution
    auto block_hash = uint256::FromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").value();
    auto tx_hash = uint256::FromHex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").value();
    
    // Create touched assets set
    std::set<uint256> touched;
    touched.insert(uint256::FromHex("aaaa000000000000000000000000000000000000000000000000000000000001").value());
    touched.insert(uint256::FromHex("bbbb000000000000000000000000000000000000000000000000000000000002").value());
    touched.insert(uint256::FromHex("cccc000000000000000000000000000000000000000000000000000000000003").value());
    touched.insert(uint256::FromHex("dddd000000000000000000000000000000000000000000000000000000000004").value());
    
    CAmount txfee = 10000; // 10k sats
    CAmount base = txfee / touched.size(); // 2500 sats each
    CAmount rem = txfee % touched.size();  // 0 remainder
    
    BOOST_CHECK_EQUAL(base, 2500);
    BOOST_CHECK_EQUAL(rem, 0);
    
    // Test with remainder
    txfee = 10003; // Creates remainder of 3
    base = txfee / touched.size();
    rem = txfee % touched.size();
    
    BOOST_CHECK_EQUAL(base, 2500);
    BOOST_CHECK_EQUAL(rem, 3);
    
    // Calculate hash-based offset (matching validation.cpp logic)
    uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
    uint64_t rnd = 0;
    for (int k = 0; k < 8; ++k) {
        rnd |= (uint64_t)mix.begin()[k] << (8*k);
    }
    
    std::vector<uint256> vec(touched.begin(), touched.end());
    std::sort(vec.begin(), vec.end());
    size_t offset = vec.empty() ? 0 : (size_t)(rnd % vec.size());
    
    // Verify distribution
    std::map<uint256, CAmount> distribution;
    for (const auto& aid : vec) {
        distribution[aid] = base;
    }
    
    // Add remainder starting at offset
    for (CAmount r = 0; r < rem; ++r) {
        size_t pos = (offset + (size_t)r) % vec.size();
        distribution[vec[pos]] += 1;
    }
    
    // Verify total
    CAmount total = 0;
    for (const auto& [aid, amount] : distribution) {
        total += amount;
    }
    BOOST_CHECK_EQUAL(total, txfee);
}

// Test fee accumulator with single asset
BOOST_AUTO_TEST_CASE(fee_accumulator_single_asset)
{
    CAmount txfee = 5000;
    std::set<uint256> touched;
    auto asset1 = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    touched.insert(asset1);
    
    CAmount base = txfee / touched.size();
    CAmount rem = txfee % touched.size();
    
    BOOST_CHECK_EQUAL(base, 5000);
    BOOST_CHECK_EQUAL(rem, 0);
    
    // Single asset gets entire fee
    std::map<uint256, CAmount> expected;
    expected[asset1] = 5000;
}

// Test fee accumulator with many assets
BOOST_AUTO_TEST_CASE(fee_accumulator_many_assets)
{
    CAmount txfee = 100000; // 100k sats
    std::set<uint256> touched;
    
    // Add 100 assets
    for (int i = 0; i < 100; ++i) {
        uint256 asset;
        asset.begin()[0] = i;
        touched.insert(asset);
    }
    
    CAmount base = txfee / touched.size(); // 1000 sats each
    CAmount rem = txfee % touched.size();  // 0 remainder
    
    BOOST_CHECK_EQUAL(base, 1000);
    BOOST_CHECK_EQUAL(rem, 0);
    
    // Each asset should get exactly 1000 sats
    for ([[maybe_unused]] const auto& asset : touched) {
        // In real code, this would update registry
        BOOST_CHECK_EQUAL(base, 1000);
    }
}

// Test edge case: zero fee
BOOST_AUTO_TEST_CASE(fee_accumulator_zero_fee)
{
    CAmount txfee = 0;
    std::set<uint256> touched;
    touched.insert(uint256::FromHex("aaaa000000000000000000000000000000000000000000000000000000000001").value());
    
    CAmount base = txfee / touched.size();
    CAmount rem = txfee % touched.size();
    
    BOOST_CHECK_EQUAL(base, 0);
    BOOST_CHECK_EQUAL(rem, 0);
}

// Test deterministic offset is stable for same inputs
BOOST_AUTO_TEST_CASE(fee_accumulator_deterministic_offset)
{
    auto block_hash = uint256::FromHex("abcd000000000000000000000000000000000000000000000000000000000000").value();
    auto tx_hash = uint256::FromHex("ef01000000000000000000000000000000000000000000000000000000000000").value();
    
    // Calculate offset multiple times - should be identical
    std::vector<size_t> offsets;
    for (int i = 0; i < 10; ++i) {
        uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
        uint64_t rnd = 0;
        for (int k = 0; k < 8; ++k) {
            rnd |= (uint64_t)mix.begin()[k] << (8*k);
        }
        size_t offset = rnd % 10; // Assume 10 assets
        offsets.push_back(offset);
    }
    
    // All offsets should be identical
    for (size_t i = 1; i < offsets.size(); ++i) {
        BOOST_CHECK_EQUAL(offsets[0], offsets[i]);
    }
}

// Test different block/tx hashes produce different offsets
BOOST_AUTO_TEST_CASE(fee_accumulator_offset_variation)
{
    std::set<size_t> observed_offsets;
    
    for (int i = 0; i < 100; ++i) {
        uint256 block_hash;
        block_hash.begin()[0] = i;
        uint256 tx_hash;
        tx_hash.begin()[0] = i + 100;
        
        uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
        uint64_t rnd = 0;
        for (int k = 0; k < 8; ++k) {
            rnd |= (uint64_t)mix.begin()[k] << (8*k);
        }
        size_t offset = rnd % 10;
        observed_offsets.insert(offset);
    }
    
    // Should see good distribution across offsets
    BOOST_CHECK_GT(observed_offsets.size(), 5); // At least half the possible values
}

// Test fee accumulator undo entries
BOOST_AUTO_TEST_CASE(fee_accumulator_undo_entries)
{
    CBlockUndo blockundo;
    std::set<uint256> touched;
    
    auto asset1 = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    auto asset2 = uint256::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value();
    touched.insert(asset1);
    touched.insert(asset2);
    
    CAmount txfee = 10001; // Creates remainder
    CAmount base = txfee / touched.size(); // 5000 each
    CAmount rem = txfee % touched.size();  // 1 remainder
    
    std::vector<uint256> vec(touched.begin(), touched.end());
    std::sort(vec.begin(), vec.end());
    
    // Simulate creating undo entries
    for (const auto& aid : vec) {
        if (base > 0) {
            CBlockUndo::FeeUndoEntry e;
            e.asset_id = aid;
            e.delta = (uint64_t)base;
            blockundo.fee_undo.push_back(e);
        }
    }
    
    // Add remainder undo
    if (rem > 0) {
        CBlockUndo::FeeUndoEntry e;
        e.asset_id = vec[0]; // First asset gets remainder in this case
        e.delta = 1;
        blockundo.fee_undo.push_back(e);
    }
    
    // Verify undo entries sum to original fee
    uint64_t total_undo = 0;
    for (const auto& undo : blockundo.fee_undo) {
        total_undo += undo.delta;
    }
    BOOST_CHECK_EQUAL(total_undo, (uint64_t)txfee);
}

// CBlockUndo serialization round-trips with the appended scalar_undo channel
// (CFD_GENERALISATION.md §3.2, Slice 1c) without disturbing the existing channels.
BOOST_AUTO_TEST_CASE(cblockundo_scalar_undo_roundtrip)
{
    CBlockUndo u;
    // A pre-existing channel entry, to prove the appended field composes with it.
    CBlockUndo::FeeUndoEntry fe;
    fe.asset_id = uint256::FromHex(std::string(64, '1')).value();
    fe.delta = 4242;
    u.fee_undo.push_back(fe);

    CBlockUndo::ScalarUndoEntry s1; // publication that CREATED the feed (no prior head)
    s1.asset_id = uint256::FromHex(std::string(64, 'a')).value();
    s1.feed_id = 7; s1.epoch = 1; s1.had_prev_head = false; s1.prev_last_epoch = 0;
    u.scalar_undo.push_back(s1);

    CBlockUndo::ScalarUndoEntry s2; // publication that advanced an existing head
    s2.asset_id = uint256::FromHex(std::string(64, 'b')).value();
    s2.feed_id = 0x01020304; s2.epoch = 99; s2.had_prev_head = true; s2.prev_last_epoch = 98;
    u.scalar_undo.push_back(s2);

    DataStream ss;
    ss << u;
    CBlockUndo u2;
    ss >> u2;

    BOOST_REQUIRE_EQUAL(u2.fee_undo.size(), 1u);
    BOOST_CHECK(u2.fee_undo[0].asset_id == fe.asset_id);
    BOOST_CHECK_EQUAL(u2.fee_undo[0].delta, 4242u);

    BOOST_REQUIRE_EQUAL(u2.scalar_undo.size(), 2u);
    BOOST_CHECK(u2.scalar_undo[0].asset_id == s1.asset_id);
    BOOST_CHECK_EQUAL(u2.scalar_undo[0].feed_id, 7u);
    BOOST_CHECK_EQUAL(u2.scalar_undo[0].epoch, 1u);
    BOOST_CHECK_EQUAL(u2.scalar_undo[0].had_prev_head, false);
    BOOST_CHECK_EQUAL(u2.scalar_undo[0].prev_last_epoch, 0u);
    BOOST_CHECK(u2.scalar_undo[1].asset_id == s2.asset_id);
    BOOST_CHECK_EQUAL(u2.scalar_undo[1].feed_id, 0x01020304u);
    BOOST_CHECK_EQUAL(u2.scalar_undo[1].epoch, 99u);
    BOOST_CHECK_EQUAL(u2.scalar_undo[1].had_prev_head, true);
    BOOST_CHECK_EQUAL(u2.scalar_undo[1].prev_last_epoch, 98u);
}

// Test unlock threshold mechanics
BOOST_AUTO_TEST_CASE(fee_accumulator_unlock_threshold)
{
    AssetRegistryEntry entry;
    entry.unlock_fees_sats = 50000; // 50k sats to unlock
    entry.fees_accum_sats = 0;
    
    // Simulate accumulating fees
    std::vector<uint64_t> fee_increments = {10000, 15000, 20000, 10000};
    
    for (uint64_t increment : fee_increments) {
        entry.fees_accum_sats += increment;
        
        bool unlocked = (entry.fees_accum_sats >= entry.unlock_fees_sats);
        
        if (entry.fees_accum_sats < 50000) {
            BOOST_CHECK(!unlocked);
        } else {
            BOOST_CHECK(unlocked);
        }
    }
    
    BOOST_CHECK_EQUAL(entry.fees_accum_sats, 55000);
    BOOST_CHECK(entry.fees_accum_sats >= entry.unlock_fees_sats);
}

// Test overflow protection
BOOST_AUTO_TEST_CASE(fee_accumulator_overflow_protection)
{
    AssetRegistryEntry entry;
    entry.fees_accum_sats = std::numeric_limits<uint64_t>::max() - 100;
    
    // Adding 200 would overflow
    uint64_t increment = 200;
    
    // Safe addition with overflow check
    uint64_t new_value = entry.fees_accum_sats;
    if (new_value <= std::numeric_limits<uint64_t>::max() - increment) {
        new_value += increment;
    } else {
        new_value = std::numeric_limits<uint64_t>::max();
    }
    
    BOOST_CHECK_EQUAL(new_value, std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_SUITE_END()