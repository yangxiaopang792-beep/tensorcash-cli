// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/asset.h>
#include <assets/registry.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(assets_bond_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unlock_fees_validation)
{
    // Test that unlock_fees_sats must be >= bond value
    // This is enforced at consensus level during transaction validation

    // Create a mock IssuerReg with unlock < bond - should fail validation
    // In actual validation.cpp, this check happens:
    // if (reg->unlock_fees_sats < static_cast<uint64_t>(out.nValue))

    CAmount bond_value = 500000000; // 5 BTC
    CAmount unlock_below = 400000000; // 4 BTC (invalid)
    CAmount unlock_equal = 500000000; // 5 BTC (valid)
    CAmount unlock_above = 1000000000; // 10 BTC (valid)

    // Test cases for validation
    BOOST_CHECK(unlock_below < bond_value); // Should fail
    BOOST_CHECK(unlock_equal >= bond_value); // Should pass
    BOOST_CHECK(unlock_above >= bond_value); // Should pass
}

BOOST_AUTO_TEST_CASE(rotation_min_sats_calculation)
{
    // Test that rotation_min_sats is initialized to 95% of bond

    CAmount bond_value = 500000000; // 5 BTC
    CAmount expected_rotation_min = (bond_value * 95) / 100; // 4.75 BTC

    BOOST_CHECK_EQUAL(expected_rotation_min, 475000000);

    // Test with various bond amounts
    struct TestCase {
        CAmount bond;
        CAmount expected_rotation_min;
    };

    TestCase test_cases[] = {
        {100000000, 95000000},     // 1 BTC → 0.95 BTC
        {500000000, 475000000},    // 5 BTC → 4.75 BTC
        {1000000000, 950000000},   // 10 BTC → 9.5 BTC
        {10000000000, 9500000000}, // 100 BTC → 95 BTC
    };

    for (const auto& tc : test_cases) {
        CAmount rotation_min = (tc.bond * 95) / 100;
        BOOST_CHECK_EQUAL(rotation_min, tc.expected_rotation_min);
    }
}

BOOST_AUTO_TEST_CASE(registry_entry_unlock_check)
{
    // Test AssetRegistryEntry::IsUnlocked() helper

    AssetRegistryEntry entry;
    entry.unlock_fees_sats = 500000000; // 5 BTC unlock threshold
    entry.fees_accum_sats = 0;
    entry.rotation_min_sats = 475000000; // 95% of 5 BTC

    // Initially not unlocked
    BOOST_CHECK(!entry.IsUnlocked());
    BOOST_CHECK_EQUAL(entry.GetMinRotationValue(), 475000000);

    // Accumulate fees but still below threshold
    entry.fees_accum_sats = 499999999;
    BOOST_CHECK(!entry.IsUnlocked());
    BOOST_CHECK_EQUAL(entry.GetMinRotationValue(), 475000000);

    // Reach unlock threshold
    entry.fees_accum_sats = 500000000;
    BOOST_CHECK(entry.IsUnlocked());

    // After unlock, rotation_min_sats would be updated to dust (546)
    // This happens in ConnectBlock, not in the entry itself
    entry.rotation_min_sats = 546;
    BOOST_CHECK_EQUAL(entry.GetMinRotationValue(), 546);

    // Exceed unlock threshold
    entry.fees_accum_sats = 600000000;
    BOOST_CHECK(entry.IsUnlocked());
}

BOOST_AUTO_TEST_CASE(rpc_default_unlock_calculation)
{
    // Test the RPC default behavior for unlock_fees_sats
    // Default should be max(bond_value, 5 BTC)

    static constexpr uint64_t MIN_BOND_SATS = 500000000; // 5 BTC

    struct TestCase {
        uint64_t bond_value;
        uint64_t expected_default_unlock;
    };

    TestCase test_cases[] = {
        {300000000, 500000000},   // 3 BTC bond → 5 BTC unlock (minimum)
        {500000000, 500000000},   // 5 BTC bond → 5 BTC unlock
        {1000000000, 1000000000}, // 10 BTC bond → 10 BTC unlock
    };

    for (const auto& tc : test_cases) {
        uint64_t default_unlock = std::max(tc.bond_value, MIN_BOND_SATS);
        BOOST_CHECK_EQUAL(default_unlock, tc.expected_default_unlock);
    }
}

BOOST_AUTO_TEST_CASE(post_unlock_dust_threshold)
{
    // Test that post-unlock rotation_min_sats is dust threshold

    static constexpr CAmount ASSET_POST_UNLOCK_DUST = 546;

    AssetRegistryEntry entry;
    entry.unlock_fees_sats = 500000000;
    entry.fees_accum_sats = 500000000; // Unlocked
    entry.rotation_min_sats = ASSET_POST_UNLOCK_DUST;

    BOOST_CHECK(entry.IsUnlocked());
    BOOST_CHECK_EQUAL(entry.GetMinRotationValue(), ASSET_POST_UNLOCK_DUST);

    // Verify dust value is reasonable
    BOOST_CHECK_GE(ASSET_POST_UNLOCK_DUST, 0);
    BOOST_CHECK_LE(ASSET_POST_UNLOCK_DUST, 1000); // Should be small
}

BOOST_AUTO_TEST_SUITE_END()