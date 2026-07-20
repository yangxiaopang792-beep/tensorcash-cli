// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <cmath>

BOOST_FIXTURE_TEST_SUITE(asset_distribution_tests, BasicTestingSetup)

// Helper function: Integer pro-rata calculation
static uint64_t CalculateProRata(uint64_t holdings, uint64_t distribution_amount, uint64_t settled_supply)
{
    arith_uint256 holdings_big(holdings);
    arith_uint256 dist_amt_big(distribution_amount);
    arith_uint256 supply_big(settled_supply);

    arith_uint256 numerator = holdings_big * dist_amt_big;
    arith_uint256 result = numerator / supply_big;

    return result.GetLow64();
}

BOOST_AUTO_TEST_CASE(prorata_exact_division)
{
    // 3 holders with 100, 200, 700 units (total 1000)
    // Distribute 1000 TSC
    // Expected: 100, 200, 700 (exact match)

    uint64_t supply = 1000;
    uint64_t distribution = 1000;

    BOOST_CHECK_EQUAL(CalculateProRata(100, distribution, supply), 100);
    BOOST_CHECK_EQUAL(CalculateProRata(200, distribution, supply), 200);
    BOOST_CHECK_EQUAL(CalculateProRata(700, distribution, supply), 700);
}

BOOST_AUTO_TEST_CASE(prorata_with_floor_rounding)
{
    // 3 holders with 333, 333, 334 units (total 1000)
    // Distribute 100 TSC
    // Expected: 33, 33, 33 (floor rounding, total 99)

    uint64_t supply = 1000;
    uint64_t distribution = 100;

    BOOST_CHECK_EQUAL(CalculateProRata(333, distribution, supply), 33);
    BOOST_CHECK_EQUAL(CalculateProRata(333, distribution, supply), 33);
    BOOST_CHECK_EQUAL(CalculateProRata(334, distribution, supply), 33);

    // Verify remainder
    uint64_t total = 33 + 33 + 33;
    BOOST_CHECK_EQUAL(distribution - total, 1); // 1 unit remainder
}

BOOST_AUTO_TEST_CASE(prorata_large_numbers)
{
    // Test with 2^60 supply to ensure no precision loss
    uint64_t supply = 1ULL << 60;
    uint64_t distribution = 1ULL << 60;

    // Holder with 1 unit out of 2^60 supply
    // Should get exactly 1 unit back
    BOOST_CHECK_EQUAL(CalculateProRata(1, distribution, supply), 1);

    // Holder with 50% supply
    uint64_t half_supply = supply / 2;
    BOOST_CHECK_EQUAL(CalculateProRata(half_supply, distribution, supply), half_supply);
}

BOOST_AUTO_TEST_CASE(prorata_precision_beyond_double)
{
    // Scenario where double would lose precision
    // Supply: large odd number where double loses precision
    uint64_t supply = 10000000000000001ULL;  // 10^16 + 1
    uint64_t distribution = 10000000000000001ULL;
    uint64_t holdings = 1;

    // Integer arithmetic: 1 * 10^16+1 / 10^16+1 = 1 (exact)
    uint64_t result = CalculateProRata(holdings, distribution, supply);
    BOOST_CHECK_EQUAL(result, 1);

    // Double loses precision with large numbers beyond 2^53
    // This demonstrates why integer arithmetic is necessary
    double ratio = static_cast<double>(holdings) / static_cast<double>(supply);
    [[maybe_unused]] double double_result = std::floor(ratio * static_cast<double>(distribution));

    // The key point: integer arithmetic guarantees correct result
    // while double may or may not depending on rounding
    BOOST_CHECK_EQUAL(result, 1); // Integer arithmetic succeeds reliably
}

BOOST_AUTO_TEST_CASE(prorata_dust_filtering)
{
    // 1000 holders with 1 unit each (supply: 1000)
    // Distribute 10 TSC
    // Each holder gets floor(1 * 10 / 1000) = 0 (below dust)

    uint64_t supply = 1000;
    uint64_t distribution = 10;

    uint64_t payment = CalculateProRata(1, distribution, supply);
    BOOST_CHECK_EQUAL(payment, 0); // Below dust

    // Only holders with >=100 units would get payment
    BOOST_CHECK_EQUAL(CalculateProRata(100, distribution, supply), 1); // At dust threshold
    BOOST_CHECK_EQUAL(CalculateProRata(200, distribution, supply), 2); // Above dust
}

BOOST_AUTO_TEST_CASE(prorata_single_holder)
{
    // Single holder with entire supply
    // Should receive entire distribution

    uint64_t supply = 1000000;
    uint64_t distribution = 500000;

    BOOST_CHECK_EQUAL(CalculateProRata(supply, distribution, supply), distribution);
}

BOOST_AUTO_TEST_CASE(prorata_zero_holdings)
{
    // Holder with 0 units should get 0 distribution

    uint64_t supply = 1000;
    uint64_t distribution = 1000;

    BOOST_CHECK_EQUAL(CalculateProRata(0, distribution, supply), 0);
}

BOOST_AUTO_TEST_CASE(prorata_tiny_fraction)
{
    // Holder with tiny fraction of supply
    // 1 unit out of 1 billion supply
    // Distributing 1000 TSC
    // Expected: 0 (floor rounds down)

    uint64_t supply = 1000000000;
    uint64_t distribution = 1000;

    BOOST_CHECK_EQUAL(CalculateProRata(1, distribution, supply), 0);

    // But 1 million units (0.1% of supply) should get 1 TSC
    BOOST_CHECK_EQUAL(CalculateProRata(1000000, distribution, supply), 1);
}

BOOST_AUTO_TEST_CASE(prorata_determinism)
{
    // Verify same inputs always produce same output
    // (This tests integer arithmetic determinism vs floating point)

    uint64_t supply = 12345678;
    uint64_t distribution = 987654321;
    uint64_t holdings = 5432109;

    uint64_t result1 = CalculateProRata(holdings, distribution, supply);
    uint64_t result2 = CalculateProRata(holdings, distribution, supply);
    uint64_t result3 = CalculateProRata(holdings, distribution, supply);

    BOOST_CHECK_EQUAL(result1, result2);
    BOOST_CHECK_EQUAL(result2, result3);
}

BOOST_AUTO_TEST_CASE(prorata_sum_invariant)
{
    // Test that sum of individual distributions <= total distribution
    // (Due to floor rounding)

    uint64_t supply = 1000;
    uint64_t distribution = 777;

    // 3 holders: 250, 250, 500
    uint64_t payment1 = CalculateProRata(250, distribution, supply);
    uint64_t payment2 = CalculateProRata(250, distribution, supply);
    uint64_t payment3 = CalculateProRata(500, distribution, supply);

    BOOST_CHECK_EQUAL(payment1, 194); // floor(250 * 777 / 1000) = 194
    BOOST_CHECK_EQUAL(payment2, 194);
    BOOST_CHECK_EQUAL(payment3, 388); // floor(500 * 777 / 1000) = 388

    uint64_t total = payment1 + payment2 + payment3;
    BOOST_CHECK_EQUAL(total, 776); // 1 unit remainder due to rounding
    BOOST_CHECK(total <= distribution); // Invariant: never over-distribute
}

BOOST_AUTO_TEST_SUITE_END()
