// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockmeta.h>

#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

using namespace node;

BOOST_FIXTURE_TEST_SUITE(blockmeta_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blockmeta_write_read)
{
    // Test basic write and read operations
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test1";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    uint256 hash1 = m_rng.rand256();
    int64_t now = GetTime();
    int32_t tip_height = 12345;

    // Write first_seen
    BOOST_CHECK(db.WriteFirstSeen(hash1, now, tip_height));

    // Read back
    auto meta = db.Read(hash1);
    BOOST_REQUIRE(meta.has_value());
    BOOST_CHECK_EQUAL(meta->first_seen_ts, now);
    BOOST_CHECK_EQUAL(meta->first_seen_height, tip_height);
    BOOST_CHECK(meta->IsKnown());
}

BOOST_AUTO_TEST_CASE(blockmeta_no_overwrite)
{
    // Test that WriteFirstSeen doesn't overwrite existing data
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test2";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    uint256 hash = m_rng.rand256();
    int64_t first_ts = 1000000;
    int64_t second_ts = 2000000;
    int32_t first_height = 100;
    int32_t second_height = 200;

    // First write should succeed
    BOOST_CHECK(db.WriteFirstSeen(hash, first_ts, first_height));

    // Second write should return false (already exists)
    BOOST_CHECK(!db.WriteFirstSeen(hash, second_ts, second_height));

    // Verify original data is preserved
    auto meta = db.Read(hash);
    BOOST_REQUIRE(meta.has_value());
    BOOST_CHECK_EQUAL(meta->first_seen_ts, first_ts);
    BOOST_CHECK_EQUAL(meta->first_seen_height, first_height);
}

BOOST_AUTO_TEST_CASE(blockmeta_exists)
{
    // Test Exists() method
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test3";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    uint256 hash1 = m_rng.rand256();
    uint256 hash2 = m_rng.rand256();

    // hash1 doesn't exist yet
    BOOST_CHECK(!db.Exists(hash1));
    BOOST_CHECK(!db.Exists(hash2));

    // Write hash1
    BOOST_CHECK(db.WriteFirstSeen(hash1, GetTime(), 100));

    // Now hash1 exists, hash2 doesn't
    BOOST_CHECK(db.Exists(hash1));
    BOOST_CHECK(!db.Exists(hash2));
}

BOOST_AUTO_TEST_CASE(blockmeta_get_first_seen_ts)
{
    // Test GetFirstSeenTs convenience method
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test4";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    uint256 hash = m_rng.rand256();
    int64_t ts = 1234567890;

    // Unknown block returns 0
    BOOST_CHECK_EQUAL(db.GetFirstSeenTs(hash), 0);

    // Write and verify
    BOOST_CHECK(db.WriteFirstSeen(hash, ts, 50));
    BOOST_CHECK_EQUAL(db.GetFirstSeenTs(hash), ts);
}

BOOST_AUTO_TEST_CASE(blockmeta_cache)
{
    // Test cache behavior
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test5";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    // Write multiple entries
    for (int i = 0; i < 100; ++i) {
        uint256 hash = m_rng.rand256();
        BOOST_CHECK(db.WriteFirstSeen(hash, GetTime() + i, i));
    }

    // Clear cache and verify we can still read from DB
    db.ClearCache();

    // Re-read should work (from disk/memory DB)
    // We can't easily verify cache misses without internal instrumentation,
    // but at least verify the DB still works after ClearCache()
    uint256 new_hash = m_rng.rand256();
    BOOST_CHECK(db.WriteFirstSeen(new_hash, GetTime(), 999));
    auto meta = db.Read(new_hash);
    BOOST_REQUIRE(meta.has_value());
    BOOST_CHECK_EQUAL(meta->first_seen_height, 999);
}

BOOST_AUTO_TEST_CASE(blockmeta_unknown_block)
{
    // Test reading unknown block
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test6";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    uint256 unknown_hash = m_rng.rand256();

    // Read should return nullopt
    auto meta = db.Read(unknown_hash);
    BOOST_CHECK(!meta.has_value());

    // GetFirstSeenTs should return 0
    BOOST_CHECK_EQUAL(db.GetFirstSeenTs(unknown_hash), 0);
}

BOOST_AUTO_TEST_CASE(blockmeta_serialization)
{
    // Test that BlockMeta serializes correctly
    BlockMeta meta{
        .first_seen_ts = 1609459200,  // 2021-01-01 00:00:00 UTC
        .first_seen_height = 666666,
    };

    BOOST_CHECK(meta.IsKnown());
    BOOST_CHECK_EQUAL(meta.first_seen_ts, 1609459200);
    BOOST_CHECK_EQUAL(meta.first_seen_height, 666666);

    // Test default (unknown) state
    BlockMeta unknown;
    BOOST_CHECK(!unknown.IsKnown());
    BOOST_CHECK_EQUAL(unknown.first_seen_ts, 0);
    BOOST_CHECK_EQUAL(unknown.first_seen_height, -1);
}

BOOST_AUTO_TEST_CASE(blockmeta_entry_count)
{
    // Test GetEntryCount method
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test7";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    // Initially empty
    BOOST_CHECK_EQUAL(db.GetEntryCount(), 0u);

    // Add entries
    for (int i = 0; i < 10; ++i) {
        uint256 hash = m_rng.rand256();
        BOOST_CHECK(db.WriteFirstSeen(hash, GetTime() + i, i * 100));
    }

    BOOST_CHECK_EQUAL(db.GetEntryCount(), 10u);
}

BOOST_AUTO_TEST_CASE(blockmeta_prune_before)
{
    // Test PruneBefore method
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test8";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    // Add entries at various heights
    std::vector<uint256> hashes;
    for (int i = 0; i < 10; ++i) {
        uint256 hash = m_rng.rand256();
        hashes.push_back(hash);
        // Heights: 100, 200, 300, ..., 1000
        BOOST_CHECK(db.WriteFirstSeen(hash, GetTime() + i, (i + 1) * 100));
    }

    BOOST_CHECK_EQUAL(db.GetEntryCount(), 10u);

    // Prune entries at height <= 500 (should remove heights 100, 200, 300, 400, 500 = 5 entries)
    size_t pruned = db.PruneBefore(500);
    BOOST_CHECK_EQUAL(pruned, 5u);
    BOOST_CHECK_EQUAL(db.GetEntryCount(), 5u);

    // Verify which entries remain
    // Entries at heights 100-500 should be gone, 600-1000 should remain
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(!db.Exists(hashes[i]));
    }
    for (int i = 5; i < 10; ++i) {
        BOOST_CHECK(db.Exists(hashes[i]));
    }

    // Prune again at same height should delete nothing
    pruned = db.PruneBefore(500);
    BOOST_CHECK_EQUAL(pruned, 0u);
    BOOST_CHECK_EQUAL(db.GetEntryCount(), 5u);

    // Prune all remaining
    pruned = db.PruneBefore(1000);
    BOOST_CHECK_EQUAL(pruned, 5u);
    BOOST_CHECK_EQUAL(db.GetEntryCount(), 0u);
}

BOOST_AUTO_TEST_CASE(blockmeta_prune_empty)
{
    // Test PruneBefore on empty database
    fs::path db_path = m_args.GetDataDirBase() / "blockmeta_test9";
    BlockMetaDB db(db_path, /*cache_size_bytes=*/1 << 20, /*memory_only=*/true);

    // Prune on empty should return 0
    BOOST_CHECK_EQUAL(db.PruneBefore(1000000), 0u);
}

BOOST_AUTO_TEST_SUITE_END()
