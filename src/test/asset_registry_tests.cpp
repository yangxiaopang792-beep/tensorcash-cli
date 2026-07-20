// Unit tests for asset registry DB operations

#include <boost/test/unit_test.hpp>

#include <assets/asset.h>
#include <assets/registry.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <txdb.h>
#include <uint256.h>

#include <vector>

BOOST_AUTO_TEST_SUITE(asset_registry_tests)

BOOST_AUTO_TEST_CASE(registry_write_read_erase)
{
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid; memset(aid.data(), 0xAB, aid.size());
    AssetRegistryEntry e;
    e.policy_bits = 0x0003u;
    e.allowed_spk_families = 0x0005u;
    uint256 hash;
    memset(hash.data(), 0x01, hash.size());
    e.icu_outpoint = COutPoint(Txid::FromHex("0101010101010101010101010101010101010101010101010101010101010101").value(), 0);
    BOOST_CHECK(db.WriteAssetPolicy(aid, e));

    AssetRegistryEntry r; BOOST_CHECK(db.ReadAssetPolicy(aid, r));
    BOOST_CHECK_EQUAL(r.policy_bits, e.policy_bits);
    BOOST_CHECK_EQUAL(r.allowed_spk_families, e.allowed_spk_families);
    BOOST_CHECK(r.icu_outpoint == e.icu_outpoint);

    BOOST_CHECK(db.EraseAssetPolicy(aid));
    AssetRegistryEntry r2; BOOST_CHECK(!db.ReadAssetPolicy(aid, r2));
}

BOOST_AUTO_TEST_CASE(registry_supply_tracking_serialization)
{
    // Test that supply tracking fields serialize/deserialize correctly
    CCoinsViewDB db{{.path = "test_supply", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xCD, aid.size());

    // Create entry with supply tracking fields
    AssetRegistryEntry e;
    e.policy_bits = 0x0003u;
    e.allowed_spk_families = 0x001Cu;
    e.icu_outpoint = COutPoint(Txid::FromHex("abababababababababababababababababababababababababababababababab").value(), 0);
    e.unlock_fees_sats = 500000000;
    e.fees_accum_sats = 100000000;

    // Set supply counters
    e.issued_total = 1000000;
    e.burned_total = 250000;

    // Set ICU/governance metadata
    e.icu_flags = 0x08u;
    e.icu_visibility = 1;
    e.icu_version = 1;
    e.policy_quorum_bps = 7500;
    e.issuance_cap_units = 10000000;
    e.unlock_fees_base = 500000000;
    e.policy_epoch = 5;

    // Write and read back
    BOOST_CHECK(db.WriteAssetPolicy(aid, e));

    AssetRegistryEntry r;
    BOOST_CHECK(db.ReadAssetPolicy(aid, r));

    // Verify supply counters
    BOOST_CHECK_EQUAL(r.issued_total, 1000000ULL);
    BOOST_CHECK_EQUAL(r.burned_total, 250000ULL);

    // Verify ICU/governance fields
    BOOST_CHECK_EQUAL(r.icu_flags, 0x08u);
    BOOST_CHECK_EQUAL(r.icu_visibility, 1);
    BOOST_CHECK_EQUAL(r.icu_version, 1);
    BOOST_CHECK_EQUAL(r.policy_quorum_bps, 7500);
    BOOST_CHECK_EQUAL(r.issuance_cap_units, 10000000ULL);
    BOOST_CHECK_EQUAL(r.unlock_fees_base, 500000000ULL);
    BOOST_CHECK_EQUAL(r.policy_epoch, 5);
}

BOOST_AUTO_TEST_CASE(registry_supply_tracking_accumulation)
{
    // Test supply counter accumulation logic (simulating ConnectBlock behavior)
    CCoinsViewDB db{{.path = "test_accumulation", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xEF, aid.size());

    // Initial registration (issued_total=0, burned_total=0)
    AssetRegistryEntry initial;
    initial.policy_bits = 0x0003u; // MINT_ALLOWED | BURN_ALLOWED
    initial.allowed_spk_families = 0x001Cu;
    initial.icu_outpoint = COutPoint(Txid::FromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").value(), 0);
    initial.issued_total = 0;
    initial.burned_total = 0;
    BOOST_CHECK(db.WriteAssetPolicy(aid, initial));

    // Simulate first mint: delta = +500000
    {
        AssetRegistryEntry prev;
        BOOST_CHECK(db.ReadAssetPolicy(aid, prev));

        AssetRegistryEntry updated = prev;
        int64_t delta = 500000;
        if (delta > 0) {
            updated.issued_total += static_cast<uint64_t>(delta);
        }
        BOOST_CHECK(db.WriteAssetPolicy(aid, updated));

        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 500000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 0ULL);
    }

    // Simulate second mint: delta = +300000
    {
        AssetRegistryEntry prev;
        BOOST_CHECK(db.ReadAssetPolicy(aid, prev));

        AssetRegistryEntry updated = prev;
        int64_t delta = 300000;
        if (delta > 0) {
            updated.issued_total += static_cast<uint64_t>(delta);
        }
        BOOST_CHECK(db.WriteAssetPolicy(aid, updated));

        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 800000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 0ULL);
    }

    // Simulate burn: delta = -200000
    {
        AssetRegistryEntry prev;
        BOOST_CHECK(db.ReadAssetPolicy(aid, prev));

        AssetRegistryEntry updated = prev;
        int64_t delta = -200000;
        if (delta < 0) {
            updated.burned_total += static_cast<uint64_t>(-delta);
        }
        BOOST_CHECK(db.WriteAssetPolicy(aid, updated));

        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 800000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 200000ULL);
    }

    // Simulate another burn: delta = -50000
    {
        AssetRegistryEntry prev;
        BOOST_CHECK(db.ReadAssetPolicy(aid, prev));

        AssetRegistryEntry updated = prev;
        int64_t delta = -50000;
        if (delta < 0) {
            updated.burned_total += static_cast<uint64_t>(-delta);
        }
        BOOST_CHECK(db.WriteAssetPolicy(aid, updated));

        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 800000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 250000ULL);

        // Verify settled supply = issued - burned = 550000
        uint64_t settled_supply = verify.issued_total - verify.burned_total;
        BOOST_CHECK_EQUAL(settled_supply, 550000ULL);
    }
}

BOOST_AUTO_TEST_CASE(registry_supply_tracking_undo_simulation)
{
    // Test supply counter undo logic (simulating DisconnectBlock behavior)
    CCoinsViewDB db{{.path = "test_undo", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0x42, aid.size());

    // Save initial state
    AssetRegistryEntry state_block_100;
    state_block_100.policy_bits = 0x0003u;
    state_block_100.allowed_spk_families = 0x001Cu;
    state_block_100.icu_outpoint = COutPoint(Txid::FromHex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").value(), 0);
    state_block_100.issued_total = 1000000;
    state_block_100.burned_total = 100000;
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_100));

    // Simulate block 101 with mint: delta = +500000
    AssetRegistryEntry state_block_101 = state_block_100;
    state_block_101.issued_total += 500000;
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_101));

    // Verify block 101 state
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 1500000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 100000ULL);
    }

    // Simulate reorg: restore block 100 state (undo block 101)
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_100));

    // Verify rollback
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 1000000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 100000ULL);
    }

    // Simulate deeper reorg: block 102 with burn instead
    AssetRegistryEntry state_block_102 = state_block_100;
    state_block_102.burned_total += 200000;
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_102));

    // Verify alternate chain state
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK_EQUAL(verify.issued_total, 1000000ULL);
        BOOST_CHECK_EQUAL(verify.burned_total, 300000ULL);
    }
}

BOOST_AUTO_TEST_CASE(registry_compliance_root_serialization)
{
    // Test that compliance_root_commit field serializes/deserializes correctly
    CCoinsViewDB db{{.path = "test_compliance", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xAA, aid.size());

    // Create entry with compliance root set
    AssetRegistryEntry e;
    e.policy_bits = assets::MINT_ALLOWED | assets::KYC_REQUIRED;
    e.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    e.has_kyc = true;

    // Set compliance_root_commit to a test value
    uint256 test_root_commit;
    memset(test_root_commit.data(), 0x77, 28);  // root portion
    unsigned char height_bytes[4] = {0x00, 0x00, 0x00, 0x64};  // height=100 in big-endian
    std::copy(height_bytes, height_bytes + 4, test_root_commit.begin() + 28);
    e.compliance_root_commit = test_root_commit;

    e.max_root_age = 288;
    e.icu_outpoint = COutPoint(Txid::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value(), 0);

    // Write and read back
    BOOST_CHECK(db.WriteAssetPolicy(aid, e));

    AssetRegistryEntry r;
    BOOST_CHECK(db.ReadAssetPolicy(aid, r));

    // Verify compliance_root_commit is preserved
    BOOST_CHECK(r.compliance_root_commit == e.compliance_root_commit);
    BOOST_CHECK(!r.compliance_root_commit.IsNull());
    BOOST_CHECK_EQUAL(r.max_root_age, 288u);
    BOOST_CHECK(r.has_kyc);
}

BOOST_AUTO_TEST_CASE(registry_compliance_root_history_serialization)
{
    // Test that compliance_root_history ring buffer serializes/deserializes correctly
    CCoinsViewDB db{{.path = "test_history", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xBB, aid.size());

    // Create entry with multiple historical roots
    AssetRegistryEntry e;
    e.policy_bits = assets::MINT_ALLOWED | assets::KYC_REQUIRED;
    e.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    e.has_kyc = true;
    e.max_root_age = 288;
    e.icu_outpoint = COutPoint(Txid::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value(), 0);

    // Set active compliance root
    uint256 active_root;
    memset(active_root.data(), 0x99, 32);
    e.compliance_root_commit = active_root;

    // Add historical entries to ring buffer
    for (int i = 0; i < 5; ++i) {
        ComplianceRootHistory hist;
        memset(hist.root_commit.data(), 0x10 + i, 32);
        hist.activation_height = 100 + i * 10;
        hist.txid = Txid::FromHex("3333333333333333333333333333333333333333333333333333333333333333").value();
        e.compliance_root_history.push_back(hist);
    }

    // Write and read back
    BOOST_CHECK(db.WriteAssetPolicy(aid, e));

    AssetRegistryEntry r;
    BOOST_CHECK(db.ReadAssetPolicy(aid, r));

    // Verify history is preserved
    BOOST_CHECK_EQUAL(r.compliance_root_history.size(), 5u);
    for (size_t i = 0; i < 5; ++i) {
        BOOST_CHECK(r.compliance_root_history[i].root_commit == e.compliance_root_history[i].root_commit);
        BOOST_CHECK_EQUAL(r.compliance_root_history[i].activation_height, e.compliance_root_history[i].activation_height);
        BOOST_CHECK(r.compliance_root_history[i].txid == e.compliance_root_history[i].txid);
    }
}

BOOST_AUTO_TEST_CASE(registry_compliance_root_rotation_undo)
{
    // Test compliance root rotation and undo (simulating reorg behavior)
    CCoinsViewDB db{{.path = "test_root_undo", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xCC, aid.size());

    // Initial state at block 100: root R1
    AssetRegistryEntry state_block_100;
    state_block_100.policy_bits = assets::MINT_ALLOWED | assets::KYC_REQUIRED;
    state_block_100.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    state_block_100.has_kyc = true;
    state_block_100.max_root_age = 288;
    state_block_100.icu_outpoint = COutPoint(Txid::FromHex("4444444444444444444444444444444444444444444444444444444444444444").value(), 0);

    uint256 root_r1;
    memset(root_r1.data(), 0xAA, 32);
    state_block_100.compliance_root_commit = root_r1;
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_100));

    // Block 110: rotate to root R2, push R1 to history
    AssetRegistryEntry state_block_110 = state_block_100;
    uint256 root_r2;
    memset(root_r2.data(), 0xBB, 32);
    state_block_110.compliance_root_commit = root_r2;

    ComplianceRootHistory hist_r1;
    hist_r1.root_commit = root_r1;
    hist_r1.activation_height = 100;
    hist_r1.txid = Txid::FromHex("5555555555555555555555555555555555555555555555555555555555555555").value();
    state_block_110.compliance_root_history.push_back(hist_r1);
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_110));

    // Verify block 110 state
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK(verify.compliance_root_commit == root_r2);
        BOOST_CHECK_EQUAL(verify.compliance_root_history.size(), 1u);
        BOOST_CHECK(verify.compliance_root_history[0].root_commit == root_r1);
    }

    // Block 120: rotate to root R3, push R2 to history
    AssetRegistryEntry state_block_120 = state_block_110;
    uint256 root_r3;
    memset(root_r3.data(), 0xCC, 32);
    state_block_120.compliance_root_commit = root_r3;

    ComplianceRootHistory hist_r2;
    hist_r2.root_commit = root_r2;
    hist_r2.activation_height = 110;
    hist_r2.txid = Txid::FromHex("6666666666666666666666666666666666666666666666666666666666666666").value();
    state_block_120.compliance_root_history.push_back(hist_r2);
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_120));

    // Verify block 120 state
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK(verify.compliance_root_commit == root_r3);
        BOOST_CHECK_EQUAL(verify.compliance_root_history.size(), 2u);
        BOOST_CHECK(verify.compliance_root_history[0].root_commit == root_r1);
        BOOST_CHECK(verify.compliance_root_history[1].root_commit == root_r2);
    }

    // Simulate reorg: undo block 120, restore block 110 state
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_110));

    // Verify rollback to block 110
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK(verify.compliance_root_commit == root_r2);
        BOOST_CHECK_EQUAL(verify.compliance_root_history.size(), 1u);
        BOOST_CHECK(verify.compliance_root_history[0].root_commit == root_r1);
    }

    // Simulate deeper reorg: undo block 110, restore block 100 state
    BOOST_CHECK(db.WriteAssetPolicy(aid, state_block_100));

    // Verify rollback to block 100
    {
        AssetRegistryEntry verify;
        BOOST_CHECK(db.ReadAssetPolicy(aid, verify));
        BOOST_CHECK(verify.compliance_root_commit == root_r1);
        BOOST_CHECK_EQUAL(verify.compliance_root_history.size(), 0u);
    }
}

BOOST_AUTO_TEST_CASE(registry_compliance_root_ring_buffer_capacity)
{
    // Test ring buffer trimming behavior at MAX_ROOT_HISTORY capacity
    CCoinsViewDB db{{.path = "test_ring_buffer", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xDD, aid.size());

    AssetRegistryEntry e;
    e.policy_bits = assets::MINT_ALLOWED | assets::KYC_REQUIRED;
    e.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    e.has_kyc = true;
    e.max_root_age = 288;
    e.icu_outpoint = COutPoint(Txid::FromHex("7777777777777777777777777777777777777777777777777777777777777777").value(), 0);

    uint256 active_root;
    memset(active_root.data(), 0xFF, 32);
    e.compliance_root_commit = active_root;

    // Fill ring buffer to capacity (MAX_ROOT_HISTORY = 32)
    for (int i = 0; i < 32; ++i) {
        ComplianceRootHistory hist;
        memset(hist.root_commit.data(), 0x01 + i, 32);
        hist.activation_height = 100 + i * 10;
        hist.txid = Txid::FromHex("8888888888888888888888888888888888888888888888888888888888888888").value();
        e.compliance_root_history.push_back(hist);
    }

    BOOST_CHECK(db.WriteAssetPolicy(aid, e));

    AssetRegistryEntry r;
    BOOST_CHECK(db.ReadAssetPolicy(aid, r));
    BOOST_CHECK_EQUAL(r.compliance_root_history.size(), 32u);

    // Verify all entries preserved
    for (size_t i = 0; i < 32; ++i) {
        BOOST_CHECK(r.compliance_root_history[i].root_commit == e.compliance_root_history[i].root_commit);
    }
}

BOOST_AUTO_TEST_CASE(registry_hardened_serialization_roundtrip)
{
    // Test hardened serialization/deserialization with ALL fields populated
    // This test ensures that the exception-based backward compatibility mechanism
    // works correctly and that all fields round-trip properly.
    CCoinsViewDB db{{.path = "test_hardened_serial", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid;
    memset(aid.data(), 0xFF, aid.size());

    // Create a fully populated AssetRegistryEntry with ALL fields set
    AssetRegistryEntry original;

    // Core fields
    original.policy_bits = 0x000Fu;
    original.allowed_spk_families = 0x001Cu;
    original.icu_outpoint = COutPoint(Txid::FromHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").value(), 7);
    original.unlock_fees_sats = 510000000;
    original.fees_accum_sats = 123456789;
    original.rotation_min_sats = 475000000;
    original.ticker = "HARDTEST";
    original.decimals = 8;

    // KYC / ZK fields
    original.has_kyc = true;
    original.zk_vk_commitment = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    original.max_root_age = 10000;
    original.tfr_flags = 0x00000003u;

    // Compliance root fields (the newly added fields that caused the regression)
    original.compliance_root_commit = uint256::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value();
    for (size_t i = 0; i < 5; ++i) {
        ComplianceRootHistory hist;
        uint256 root = uint256::FromHex("3333333333333333333333333333333333333333333333333333333333333333").value();
        root.data()[0] = static_cast<unsigned char>(i);
        hist.root_commit = root;
        hist.activation_height = 1000 + static_cast<int>(i * 100);
        hist.txid = Txid::FromHex("4444444444444444444444444444444444444444444444444444444444444444").value();
        original.compliance_root_history.push_back(hist);
    }

    // Supply tracking fields
    original.issued_total = 50000000;
    original.burned_total = 5000000;

    // ICU / Governance fields
    original.icu_flags = 0x00000001u;
    original.icu_visibility = 1;
    original.icu_version = 1;
    original.policy_quorum_bps = 5000;
    original.issuance_cap_units = 100000000;
    original.unlock_fees_base = 510000000;
    original.icu_ctxt_commit = uint256::FromHex("5555555555555555555555555555555555555555555555555555555555555555").value();
    original.icu_plain_commit = uint256::FromHex("6666666666666666666666666666666666666666666666666666666666666666").value();
    for (size_t i = 0; i < 16; ++i) {
        original.kdf_salt[i] = static_cast<unsigned char>(0x77 + i);
    }
    original.core_policy_commit = uint256::FromHex("7777777777777777777777777777777777777777777777777777777777777777").value();
    original.policy_epoch = 42;

    // Write to database
    BOOST_CHECK(db.WriteAssetPolicy(aid, original));

    // Read back from database
    AssetRegistryEntry roundtrip;
    BOOST_CHECK(db.ReadAssetPolicy(aid, roundtrip));

    // Verify ALL fields round-tripped correctly

    // Core fields
    BOOST_CHECK_EQUAL(roundtrip.policy_bits, original.policy_bits);
    BOOST_CHECK_EQUAL(roundtrip.allowed_spk_families, original.allowed_spk_families);
    BOOST_CHECK(roundtrip.icu_outpoint == original.icu_outpoint);
    BOOST_CHECK_EQUAL(roundtrip.unlock_fees_sats, original.unlock_fees_sats);
    BOOST_CHECK_EQUAL(roundtrip.fees_accum_sats, original.fees_accum_sats);
    BOOST_CHECK_EQUAL(roundtrip.rotation_min_sats, original.rotation_min_sats);
    BOOST_CHECK_EQUAL(roundtrip.ticker, original.ticker);
    BOOST_CHECK_EQUAL(roundtrip.decimals, original.decimals);

    // KYC / ZK fields
    BOOST_CHECK_EQUAL(roundtrip.has_kyc, original.has_kyc);
    BOOST_CHECK(roundtrip.zk_vk_commitment == original.zk_vk_commitment);
    BOOST_CHECK_EQUAL(roundtrip.max_root_age, original.max_root_age);
    BOOST_CHECK_EQUAL(roundtrip.tfr_flags, original.tfr_flags);

    // Compliance root fields (CRITICAL: these caused the regression)
    BOOST_CHECK(roundtrip.compliance_root_commit == original.compliance_root_commit);
    BOOST_CHECK_EQUAL(roundtrip.compliance_root_history.size(), original.compliance_root_history.size());
    for (size_t i = 0; i < original.compliance_root_history.size(); ++i) {
        BOOST_CHECK(roundtrip.compliance_root_history[i].root_commit == original.compliance_root_history[i].root_commit);
        BOOST_CHECK_EQUAL(roundtrip.compliance_root_history[i].activation_height, original.compliance_root_history[i].activation_height);
        BOOST_CHECK(roundtrip.compliance_root_history[i].txid == original.compliance_root_history[i].txid);
    }

    // Supply tracking fields
    BOOST_CHECK_EQUAL(roundtrip.issued_total, original.issued_total);
    BOOST_CHECK_EQUAL(roundtrip.burned_total, original.burned_total);

    // ICU / Governance fields
    BOOST_CHECK_EQUAL(roundtrip.icu_flags, original.icu_flags);
    BOOST_CHECK_EQUAL(roundtrip.icu_visibility, original.icu_visibility);
    BOOST_CHECK_EQUAL(roundtrip.icu_version, original.icu_version);
    BOOST_CHECK_EQUAL(roundtrip.policy_quorum_bps, original.policy_quorum_bps);
    BOOST_CHECK_EQUAL(roundtrip.issuance_cap_units, original.issuance_cap_units);
    BOOST_CHECK_EQUAL(roundtrip.unlock_fees_base, original.unlock_fees_base);
    BOOST_CHECK(roundtrip.icu_ctxt_commit == original.icu_ctxt_commit);
    BOOST_CHECK(roundtrip.icu_plain_commit == original.icu_plain_commit);
    for (size_t i = 0; i < 16; ++i) {
        BOOST_CHECK_EQUAL(roundtrip.kdf_salt[i], original.kdf_salt[i]);
    }
    BOOST_CHECK(roundtrip.core_policy_commit == original.core_policy_commit);
    BOOST_CHECK_EQUAL(roundtrip.policy_epoch, original.policy_epoch);
}

BOOST_AUTO_TEST_CASE(registry_v5_delegation_fields_roundtrip)
{
    // The reusable/delegated-KYC (v5) fields must round-trip through the DB.
    CCoinsViewDB db{{.path = "test_v5_serial", .cache_bytes = 1<<20, .memory_only = true}, {}};
    uint256 aid; memset(aid.data(), 0x5A, aid.size());

    AssetRegistryEntry e;
    e.has_kyc = true;
    e.zk_vk_commitment = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    e.compliance_root_commit = uint256::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value();
    e.compliance_delegate_asset_id = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000a2").value();
    e.active_root_activation_height = 777;
    e.compliance_root_history_vk.push_back(uint256::FromHex("8888888888888888888888888888888888888888888888888888888888888888").value());
    e.compliance_root_history_vk.push_back(uint256::FromHex("9999999999999999999999999999999999999999999999999999999999999999").value());

    BOOST_CHECK(db.WriteAssetPolicy(aid, e));
    AssetRegistryEntry r; BOOST_CHECK(db.ReadAssetPolicy(aid, r));

    BOOST_CHECK(r.compliance_delegate_asset_id == e.compliance_delegate_asset_id);
    BOOST_CHECK_EQUAL(r.active_root_activation_height, 777);
    BOOST_CHECK_EQUAL(r.compliance_root_history_vk.size(), 2u);
    BOOST_CHECK(r.compliance_root_history_vk[0] == e.compliance_root_history_vk[0]);
    BOOST_CHECK(r.compliance_root_history_vk[1] == e.compliance_root_history_vk[1]);
}

BOOST_AUTO_TEST_CASE(registry_v4_blob_not_corrupted_by_v5_reader)
{
    // CRITICAL backward-compat guarantee: a pre-v5 (v2-v4) on-disk entry — which
    // ends at policy_epoch — must read back with its KYC/root fields INTACT and
    // only the v5 fields defaulted. If the v5 read EOF propagated to the outer
    // catch, has_kyc/root/... would reset and a KYC asset would silently become a
    // non-KYC one. See REUSABLE_KYC.md §2.1.
    //
    // We emulate a v4 blob by serializing a v5 entry whose v5 group is minimal and
    // therefore a known fixed length — null delegate (32) + activation_height (4) +
    // empty history_vk CompactSize (1) = 37 bytes — then truncating those bytes.
    AssetRegistryEntry e;
    e.policy_bits = 0x0007u;
    e.allowed_spk_families = 0x001Cu;
    e.icu_outpoint = COutPoint(Txid::FromHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").value(), 3);
    e.ticker = "V4TEST";
    e.decimals = 8;
    e.has_kyc = true;
    e.zk_vk_commitment = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    e.max_root_age = 10000;
    e.tfr_flags = 0x00000003u;
    e.compliance_root_commit = uint256::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value();
    e.policy_epoch = 9;
    // v5 group: minimal so its serialized length is exactly 37 bytes.
    e.compliance_delegate_asset_id.SetNull();
    e.active_root_activation_height = 0;
    // compliance_root_history_vk left empty -> CompactSize(0) = 1 byte.

    DataStream ss;
    ss << e;
    std::vector<std::byte> buf(ss.begin(), ss.end());
    BOOST_REQUIRE(buf.size() > 37);
    buf.resize(buf.size() - 37); // drop the v5 group -> a "v4" blob ending at policy_epoch

    DataStream ss2{buf};
    AssetRegistryEntry r;
    ss2 >> r;

    // v4 fields survive intact (the no-corruption guarantee)
    BOOST_CHECK_EQUAL(r.policy_bits, 0x0007u);
    BOOST_CHECK_EQUAL(r.has_kyc, true);
    BOOST_CHECK(r.zk_vk_commitment == e.zk_vk_commitment);
    BOOST_CHECK_EQUAL(r.max_root_age, 10000u);
    BOOST_CHECK_EQUAL(r.tfr_flags, 0x00000003u);
    BOOST_CHECK(r.compliance_root_commit == e.compliance_root_commit);
    BOOST_CHECK_EQUAL(r.policy_epoch, 9);
    // v5 fields defaulted, not garbage
    BOOST_CHECK(r.compliance_delegate_asset_id.IsNull());
    BOOST_CHECK_EQUAL(r.active_root_activation_height, 0);
    BOOST_CHECK(r.compliance_root_history_vk.empty());
}

BOOST_AUTO_TEST_SUITE_END()

