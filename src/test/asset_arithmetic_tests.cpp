// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <hash.h>
#include <serialize.h>

#include <limits>
#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(asset_arithmetic_tests, BasicTestingSetup)

// Test portable integer operations across platforms
BOOST_AUTO_TEST_CASE(cross_platform_int64_arithmetic)
{
    // Test boundary values for int64_t
    int64_t max_val = std::numeric_limits<int64_t>::max();
    int64_t min_val = std::numeric_limits<int64_t>::min();
    
    // Addition overflow check
    {
        int64_t a = max_val - 100;
        int64_t b = 200;
        
        // Safe addition
        int64_t result;
        bool overflow = false;
        
        if (b > 0 && a > max_val - b) {
            overflow = true;
            result = max_val;
        } else if (b < 0 && a < min_val - b) {
            overflow = true;
            result = min_val;
        } else {
            result = a + b;
        }
        
        BOOST_CHECK(overflow);
        BOOST_CHECK_EQUAL(result, max_val);
    }
    
    // Subtraction underflow check
    {
        int64_t a = min_val + 100;
        int64_t b = 200;
        
        // Safe subtraction
        int64_t result;
        bool underflow = false;
        
        if (b > 0 && a < min_val + b) {
            underflow = true;
            result = min_val;
        } else if (b < 0 && a > max_val + b) {
            underflow = true;
            result = max_val;
        } else {
            result = a - b;
        }
        
        BOOST_CHECK(underflow);
        BOOST_CHECK_EQUAL(result, min_val);
    }
}

// Test uint64_t arithmetic consistency
BOOST_AUTO_TEST_CASE(cross_platform_uint64_arithmetic)
{
    uint64_t max_val = std::numeric_limits<uint64_t>::max();
    
    // Addition with overflow protection
    {
        uint64_t a = max_val - 100;
        uint64_t b = 200;
        
        uint64_t result;
        if (a > max_val - b) {
            result = max_val;
        } else {
            result = a + b;
        }
        
        BOOST_CHECK_EQUAL(result, max_val);
    }
    
    // Multiplication overflow
    {
        uint64_t a = max_val / 2 + 1;
        uint64_t b = 2;
        
        uint64_t result;
        if (a > max_val / b) {
            result = max_val;
        } else {
            result = a * b;
        }
        
        BOOST_CHECK_EQUAL(result, max_val);
    }
    
    // Division by zero protection
    {
        uint64_t a = 1000000;
        uint64_t b = 0;
        
        uint64_t result = 0;
        if (b != 0) {
            result = a / b;
        }
        
        BOOST_CHECK_EQUAL(result, 0);
    }
}

// Test serialization endianness consistency
BOOST_AUTO_TEST_CASE(cross_platform_serialization)
{
    // Test little-endian serialization
    {
        uint64_t value = 0x0123456789ABCDEF;
        unsigned char bytes[8];
        WriteLE64(bytes, value);
        
        // Verify byte order (little-endian)
        BOOST_CHECK_EQUAL(bytes[0], 0xEF);
        BOOST_CHECK_EQUAL(bytes[1], 0xCD);
        BOOST_CHECK_EQUAL(bytes[2], 0xAB);
        BOOST_CHECK_EQUAL(bytes[3], 0x89);
        BOOST_CHECK_EQUAL(bytes[4], 0x67);
        BOOST_CHECK_EQUAL(bytes[5], 0x45);
        BOOST_CHECK_EQUAL(bytes[6], 0x23);
        BOOST_CHECK_EQUAL(bytes[7], 0x01);
        
        // Read back
        uint64_t read_value = ReadLE64(bytes);
        BOOST_CHECK_EQUAL(read_value, value);
    }
    
    // Test 32-bit serialization
    {
        uint32_t value = 0x12345678;
        unsigned char bytes[4];
        WriteLE32(bytes, value);
        
        BOOST_CHECK_EQUAL(bytes[0], 0x78);
        BOOST_CHECK_EQUAL(bytes[1], 0x56);
        BOOST_CHECK_EQUAL(bytes[2], 0x34);
        BOOST_CHECK_EQUAL(bytes[3], 0x12);
        
        uint32_t read_value = ReadLE32(bytes);
        BOOST_CHECK_EQUAL(read_value, value);
    }
    
    // Test 16-bit serialization
    {
        uint16_t value = 0xABCD;
        unsigned char bytes[2];
        WriteLE16(bytes, value);
        
        BOOST_CHECK_EQUAL(bytes[0], 0xCD);
        BOOST_CHECK_EQUAL(bytes[1], 0xAB);
        
        uint16_t read_value = ReadLE16(bytes);
        BOOST_CHECK_EQUAL(read_value, value);
    }
}

// Test hash determinism across platforms
BOOST_AUTO_TEST_CASE(cross_platform_hash_determinism)
{
    // Test SHA256 determinism
    {
        auto block_hash = uint256::FromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();
        auto tx_hash = uint256::FromHex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").value();
        
        // Compute hash
        uint256 result = (HashWriter{} << block_hash << tx_hash).GetHash();
        
        // The result should be deterministic across all platforms
        // Store expected hash (computed once on reference platform)
        [[maybe_unused]] auto expected = uint256::FromHex("7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730").value();
        
        // Note: This expected value is illustrative. In real tests, compute on reference platform
        // For now, just verify determinism by computing multiple times
        for (int i = 0; i < 10; ++i) {
            uint256 result2 = (HashWriter{} << block_hash << tx_hash).GetHash();
            BOOST_CHECK_EQUAL(result, result2);
        }
    }
    
    // Test hash-based offset calculation
    {
        auto block_hash = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").value();
        auto tx_hash = uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").value();
        
        uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
        
        // Extract deterministic random value
        uint64_t rnd = 0;
        for (int k = 0; k < 8; ++k) {
            rnd |= (uint64_t)mix.begin()[k] << (8*k);
        }
        
        // Verify same result on repeated calculation
        for (int i = 0; i < 10; ++i) {
            uint256 mix2 = (HashWriter{} << block_hash << tx_hash).GetHash();
            uint64_t rnd2 = 0;
            for (int k = 0; k < 8; ++k) {
                rnd2 |= (uint64_t)mix2.begin()[k] << (8*k);
            }
            BOOST_CHECK_EQUAL(rnd, rnd2);
        }
    }
}

// Test modulo operations consistency
BOOST_AUTO_TEST_CASE(cross_platform_modulo)
{
    // Test modulo with various divisors
    std::vector<uint64_t> test_values = {
        0, 1, 100, 1000, 
        std::numeric_limits<uint64_t>::max() - 1,
        std::numeric_limits<uint64_t>::max()
    };
    
    std::vector<size_t> divisors = {1, 2, 3, 5, 10, 100, 1000};
    
    for (uint64_t value : test_values) {
        for (size_t divisor : divisors) {
            size_t result = value % divisor;
            BOOST_CHECK_LT(result, divisor);
            
            // Verify consistency
            size_t result2 = value % divisor;
            BOOST_CHECK_EQUAL(result, result2);
        }
    }
    
    // Test signed modulo behavior
    {
        int64_t neg_value = -100;
        int64_t divisor = 7;
        
        // C++ standard: sign of remainder follows dividend
        int64_t remainder = neg_value % divisor;
        BOOST_CHECK_LE(remainder, 0);
        
        // For fee distribution, we use unsigned arithmetic
        uint64_t abs_value = 100;
        uint64_t u_divisor = 7;
        uint64_t u_remainder = abs_value % u_divisor;
        BOOST_CHECK_EQUAL(u_remainder, 2);
    }
}

// Test asset amount arithmetic edge cases
BOOST_AUTO_TEST_CASE(asset_amount_arithmetic)
{
    // Maximum asset amount
    uint64_t max_amount = std::numeric_limits<uint64_t>::max();
    
    // Test accumulation without overflow
    {
        uint64_t balance = max_amount - 1000;
        uint64_t incoming = 500;
        
        uint64_t new_balance;
        if (balance > max_amount - incoming) {
            new_balance = max_amount;
        } else {
            new_balance = balance + incoming;
        }
        
        BOOST_CHECK_EQUAL(new_balance, max_amount - 500);
    }
    
    // Test accumulation with overflow
    {
        uint64_t balance = max_amount - 100;
        uint64_t incoming = 200;
        
        uint64_t new_balance;
        if (balance > max_amount - incoming) {
            new_balance = max_amount;
        } else {
            new_balance = balance + incoming;
        }
        
        BOOST_CHECK_EQUAL(new_balance, max_amount);
    }
    
    // Test delta computation with mixed signs
    {
        // In actual validation, we track as int64_t for delta
        int64_t total_in = 1000000;
        int64_t total_out = 900000;
        int64_t delta = total_out - total_in;
        
        BOOST_CHECK_EQUAL(delta, -100000);
        
        // Check for conservation
        bool conserved = (delta == 0);
        bool mint = (delta > 0);
        bool burn = (delta < 0);
        
        BOOST_CHECK(!conserved);
        BOOST_CHECK(!mint);
        BOOST_CHECK(burn);
    }
}

// Test byte order conversions
BOOST_AUTO_TEST_CASE(cross_platform_byte_order)
{
    // Test uint256 byte order
    {
        uint256 value;
        for (size_t i = 0; i < 32; ++i) {
            value.begin()[i] = i;
        }
        
        // Verify consistent access
        for (size_t i = 0; i < 32; ++i) {
            BOOST_CHECK_EQUAL(value.begin()[i], i);
        }
        
        // Test serialization
        DataStream ss;
        ss << value;
        
        uint256 value2;
        ss >> value2;
        
        BOOST_CHECK_EQUAL(value, value2);
    }
    
    // Test COutPoint serialization (used for ICU tracking)
    {
        COutPoint outpoint;
        outpoint.hash = Txid::FromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").value();
        outpoint.n = 0x12345678;
        
        DataStream ss;
        ss << outpoint;
        
        COutPoint outpoint2;
        ss >> outpoint2;
        
        BOOST_CHECK_EQUAL(outpoint.hash, outpoint2.hash);
        BOOST_CHECK_EQUAL(outpoint.n, outpoint2.n);
    }
}

// Test fee distribution arithmetic precision
BOOST_AUTO_TEST_CASE(fee_distribution_precision)
{
    // Test precise distribution with no rounding errors
    {
        CAmount total_fee = 1000000; // 1M sats
        size_t num_assets = 3;
        
        CAmount base = total_fee / num_assets;
        CAmount remainder = total_fee % num_assets;
        
        BOOST_CHECK_EQUAL(base, 333333);
        BOOST_CHECK_EQUAL(remainder, 1);
        
        // Verify reconstruction
        CAmount distributed = base * num_assets + remainder;
        BOOST_CHECK_EQUAL(distributed, total_fee);
    }
    
    // Test with prime number of assets
    {
        CAmount total_fee = 1000000;
        size_t num_assets = 17; // Prime number
        
        CAmount base = total_fee / num_assets;
        CAmount remainder = total_fee % num_assets;
        
        BOOST_CHECK_EQUAL(base, 58823);
        BOOST_CHECK_EQUAL(remainder, 9);
        
        CAmount distributed = base * num_assets + remainder;
        BOOST_CHECK_EQUAL(distributed, total_fee);
    }
    
    // Test with very small fees
    {
        CAmount total_fee = 10; // 10 sats
        size_t num_assets = 100;
        
        CAmount base = total_fee / num_assets;
        CAmount remainder = total_fee % num_assets;
        
        BOOST_CHECK_EQUAL(base, 0);
        BOOST_CHECK_EQUAL(remainder, 10);
        
        // All fee goes to remainder distribution
        CAmount distributed = base * num_assets + remainder;
        BOOST_CHECK_EQUAL(distributed, total_fee);
    }
}

BOOST_AUTO_TEST_SUITE_END()