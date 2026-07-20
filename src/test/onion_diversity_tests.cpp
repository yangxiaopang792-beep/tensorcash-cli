// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <onion_diversity.h>

#include <chain.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <unordered_set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(onion_diversity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(block_hash_to_base32_tag_determinism)
{
    // Known hash -> deterministic tag
    uint256 hash{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};
    std::string tag3 = BlockHashToBase32Tag(hash, 3);
    BOOST_CHECK_EQUAL(tag3.size(), 3u);

    // Same hash, same length -> same result
    BOOST_CHECK_EQUAL(tag3, BlockHashToBase32Tag(hash, 3));

    // Different length -> different size
    std::string tag5 = BlockHashToBase32Tag(hash, 5);
    BOOST_CHECK_EQUAL(tag5.size(), 5u);

    // Longer tag starts with shorter tag (same prefix bytes)
    BOOST_CHECK_EQUAL(tag5.substr(0, 3), tag3);
}

BOOST_AUTO_TEST_CASE(block_hash_to_base32_tag_different_hashes)
{
    uint256 h1{"0000000000000000000000000000000000000000000000000000000000000001"};
    uint256 h2{"0000000000000000000000000000000000000000000000000000000000000002"};

    std::string t1 = BlockHashToBase32Tag(h1, 3);
    std::string t2 = BlockHashToBase32Tag(h2, 3);
    BOOST_CHECK_EQUAL(t1.size(), 3u);
    BOOST_CHECK_EQUAL(t2.size(), 3u);
}

BOOST_AUTO_TEST_CASE(onion_to_diversity_key_high_bit)
{
    // High bit must always be set
    BOOST_CHECK(OnionToDiversityKey("tensorc2abcdefghijklmnopqrstuvwxyz234567.onion") & (1ULL << 63));
    BOOST_CHECK(OnionToDiversityKey("tensorc5xyzabcdefghijklmnopqrstuvwxyz234567.onion") & (1ULL << 63));
    BOOST_CHECK(OnionToDiversityKey("someother.onion") & (1ULL << 63));
}

BOOST_AUTO_TEST_CASE(onion_to_diversity_key_determinism)
{
    std::string addr = "tensorcabcdefghijklmnopqrstuvwxyz234567.onion";
    BOOST_CHECK_EQUAL(OnionToDiversityKey(addr), OnionToDiversityKey(addr));
}

BOOST_AUTO_TEST_CASE(onion_to_diversity_key_uniqueness)
{
    uint64_t k1 = OnionToDiversityKey("tensorc2abcdefghijklmnopqrstuvwxyz234567.onion");
    uint64_t k2 = OnionToDiversityKey("tensorc5xyzabcdefghijklmnopqrstuvwxyz234567.onion");
    BOOST_CHECK(k1 != k2);
}

BOOST_AUTO_TEST_CASE(onion_to_diversity_key_no_asn_collision)
{
    uint64_t key = OnionToDiversityKey("tensorc2abcdefghijklmnopqrstuvwxyz234567.onion");
    BOOST_CHECK(key >= (1ULL << 63));
    // Maximum possible ASN value is uint32_t max
    BOOST_CHECK(key > uint64_t{0xFFFFFFFF});
}

BOOST_AUTO_TEST_CASE(diversity_set_coexistence)
{
    // uint64_t ASN values and onion keys coexist without collision
    std::unordered_set<uint64_t> diversity_set;

    diversity_set.insert(uint64_t{12345});
    diversity_set.insert(uint64_t{67890});

    uint64_t ok1 = OnionToDiversityKey("tensorc2abcdefghijklmnopqrstuvwxyz234567.onion");
    uint64_t ok2 = OnionToDiversityKey("tensorc5xyzabcdefghijklmnopqrstuvwxyz234567.onion");
    diversity_set.insert(ok1);
    diversity_set.insert(ok2);

    BOOST_CHECK_EQUAL(diversity_set.size(), 4u);
}

//
// Freshness tests using a real CChain with CBlockIndex entries
//

namespace {

// Helper: build a small chain of N blocks with known hashes, return the
// block indices (caller owns them) and the populated CChain.
// Each block hash is set to `base_hash XOR height` for determinism.
struct TestChain {
    std::vector<CBlockIndex> indices;
    std::vector<uint256> hashes;
    CChain chain;

    explicit TestChain(int num_blocks) : indices(num_blocks), hashes(num_blocks)
    {
        for (int i = 0; i < num_blocks; ++i) {
            // Create a deterministic but distinct hash for each height
            hashes[i].SetNull();
            // Put height into the first few bytes so tags differ
            unsigned char* data = hashes[i].data();
            data[0] = static_cast<unsigned char>(i & 0xFF);
            data[1] = static_cast<unsigned char>((i >> 8) & 0xFF);
            data[2] = static_cast<unsigned char>((i >> 16) & 0xFF);
            data[3] = static_cast<unsigned char>(0xAB); // sentinel

            indices[i].phashBlock = &hashes[i];
            indices[i].nHeight = i;
            if (i > 0) indices[i].pprev = &indices[i - 1];
        }
        // SetTip populates the internal vector so operator[] works
        chain.SetTip(indices.back());
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(check_onion_freshness_positive)
{
    // Build a chain of 10 blocks (heights 0..9)
    TestChain tc(10);

    // Derive the tag that block at height 5 would produce
    std::string tag = BlockHashToBase32Tag(tc.hashes[5], 3);

    // Construct an onion address with the correct prefix + tag
    std::string onion = "tensorc" + tag + "restoftheaddress.onion";

    // Should pass: block 5 is within window of 100 from tip at height 9
    BOOST_CHECK(CheckOnionFreshness(onion, &tc.indices[9], 100, "tensorc", 3));
}

BOOST_AUTO_TEST_CASE(check_onion_freshness_stale_tag)
{
    // Build a chain of 100 blocks (heights 0..99)
    TestChain tc(100);

    // Derive tag from block at height 5
    std::string tag = BlockHashToBase32Tag(tc.hashes[5], 3);
    std::string onion = "tensorc" + tag + "restoftheaddress.onion";

    // Window is 9 blocks back from tip 99 — block 5 is outside [90, 99]
    BOOST_CHECK(!CheckOnionFreshness(onion, &tc.indices[99], 9, "tensorc", 3));
}

BOOST_AUTO_TEST_CASE(check_onion_freshness_wrong_prefix)
{
    BOOST_CHECK(!CheckOnionFreshness("wrongprefix.onion", nullptr, 100, "tensorc", 3));
}

BOOST_AUTO_TEST_CASE(check_onion_freshness_too_short)
{
    BOOST_CHECK(!CheckOnionFreshness("tensor", nullptr, 100, "tensorc", 3));
}

BOOST_AUTO_TEST_CASE(check_onion_freshness_edge_of_window)
{
    // Build chain of 20 blocks
    TestChain tc(20);

    // Tag from block at height 10.  CheckOnionFreshness scans `window`
    // blocks backwards from tip (inclusive), so window=6 from tip 15 covers
    // heights {15,14,13,12,11,10}.
    std::string tag = BlockHashToBase32Tag(tc.hashes[10], 3);
    std::string onion = "tensorc" + tag + "rest.onion";

    // Tip at height 15, window 6: scan [10, 15] — height 10 is at boundary, should pass
    BOOST_CHECK(CheckOnionFreshness(onion, &tc.indices[15], 6, "tensorc", 3));

    // Tip at height 16, window 6: scan [11, 16] — height 10 is outside, should fail
    BOOST_CHECK(!CheckOnionFreshness(onion, &tc.indices[16], 6, "tensorc", 3));
}

BOOST_AUTO_TEST_CASE(check_onion_freshness_tag_from_tip)
{
    TestChain tc(10);

    // Tag derived from the tip itself (height 9)
    std::string tag = BlockHashToBase32Tag(tc.hashes[9], 3);
    std::string onion = "tensorc" + tag + "whatever.onion";

    BOOST_CHECK(CheckOnionFreshness(onion, &tc.indices[9], 1, "tensorc", 3));
}

BOOST_AUTO_TEST_SUITE_END()
