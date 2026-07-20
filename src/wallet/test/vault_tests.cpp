// Copyright (c) 2024-present TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/vaultregistry.h>

#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <optional>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(vault_tests, WalletTestingSetup)

// Helper: Create a simple P2TR output key
static XOnlyPubKey CreateTestXOnlyKey()
{
    CKey key;
    key.MakeNewKey(true);
    return XOnlyPubKey(key.GetPubKey());
}

// Helper: Create a test leaf script
static CScript CreateTestLeafScript(const XOnlyPubKey& key, uint32_t locktime = 0)
{
    CScript script;
    if (locktime > 0) {
        script << CScriptNum(locktime) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    }
    script << std::vector<unsigned char>(key.begin(), key.end()) << OP_CHECKSIG;
    return script;
}

// ============================================================================
// VaultLeafDescriptor Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(leaf_descriptor_validation)
{
    XOnlyPubKey valid_key = CreateTestXOnlyKey();
    CScript valid_script = CreateTestLeafScript(valid_key);

    // Valid leaf
    VaultLeafDescriptor valid_leaf;
    valid_leaf.script = std::vector<unsigned char>(valid_script.begin(), valid_script.end());
    valid_leaf.leaf_version = TAPROOT_LEAF_TAPSCRIPT;
    valid_leaf.signing_key = valid_key;
    valid_leaf.purpose = "test";
    valid_leaf.timelock = std::nullopt;

    BOOST_CHECK(valid_leaf.Validate());

    // Invalid: Empty script
    VaultLeafDescriptor empty_script_leaf = valid_leaf;
    empty_script_leaf.script.clear();
    BOOST_CHECK(!empty_script_leaf.Validate());

    // Invalid: Wrong leaf version
    VaultLeafDescriptor wrong_version_leaf = valid_leaf;
    wrong_version_leaf.leaf_version = 0xFF;
    BOOST_CHECK(!wrong_version_leaf.Validate());

    // Invalid: a non-null but off-curve signing key (32 bytes that are not a valid x-only point).
    VaultLeafDescriptor bad_key_leaf = valid_leaf;
    std::vector<unsigned char> off_curve(32, 0xFF); // >= field prime p -> not a valid x-coordinate
    bad_key_leaf.signing_key = XOnlyPubKey(std::span<const unsigned char>(off_curve.data(), 32));
    BOOST_CHECK(!bad_key_leaf.IsCovenantOnly());
    BOOST_CHECK(!bad_key_leaf.Validate());

    // Invalid: Empty purpose
    VaultLeafDescriptor empty_purpose_leaf = valid_leaf;
    empty_purpose_leaf.purpose = "";
    BOOST_CHECK(!empty_purpose_leaf.Validate());
}

// A covenant-only leaf (all-zero signing_key sentinel) is signatureless / keeper-spendable and must
// validate without a signing key — this is the difficulty-derivative unilateral settlement leaf.
BOOST_AUTO_TEST_CASE(leaf_descriptor_covenant_only)
{
    CScript script = CreateTestLeafScript(CreateTestXOnlyKey());

    VaultLeafDescriptor leaf;
    leaf.script = std::vector<unsigned char>(script.begin(), script.end());
    leaf.leaf_version = TAPROOT_LEAF_TAPSCRIPT;
    leaf.signing_key = XOnlyPubKey(); // null sentinel -> covenant-only
    leaf.purpose = "difficulty-settle";
    leaf.timelock = std::nullopt;

    BOOST_CHECK(leaf.IsCovenantOnly());
    BOOST_CHECK(leaf.Validate()); // valid despite having no signing key

    // A leaf with a real key is NOT covenant-only.
    VaultLeafDescriptor keyed = leaf;
    keyed.signing_key = CreateTestXOnlyKey();
    BOOST_CHECK(!keyed.IsCovenantOnly());
    BOOST_CHECK(keyed.Validate());

    // Covenant-only still requires the other invariants (script / version / purpose).
    VaultLeafDescriptor empty_script = leaf;
    empty_script.script.clear();
    BOOST_CHECK(!empty_script.Validate());
}

BOOST_AUTO_TEST_CASE(leaf_descriptor_serialization_roundtrip)
{
    XOnlyPubKey key = CreateTestXOnlyKey();
    CScript script = CreateTestLeafScript(key, 12345);

    VaultLeafDescriptor original;
    original.script = std::vector<unsigned char>(script.begin(), script.end());
    original.leaf_version = TAPROOT_LEAF_TAPSCRIPT;
    original.signing_key = key;
    original.purpose = "timeout";
    original.timelock = 12345;

    // Serialize
    DataStream ss{};
    ss << original;

    // Deserialize
    VaultLeafDescriptor deserialized;
    ss >> deserialized;

    // Verify all fields match
    BOOST_CHECK(original.script == deserialized.script);
    BOOST_CHECK(original.leaf_version == deserialized.leaf_version);
    BOOST_CHECK(original.signing_key == deserialized.signing_key);
    BOOST_CHECK(original.purpose == deserialized.purpose);
    BOOST_CHECK(original.timelock == deserialized.timelock);
}

BOOST_AUTO_TEST_CASE(leaf_descriptor_optional_timelock_serialization)
{
    XOnlyPubKey key = CreateTestXOnlyKey();
    CScript script = CreateTestLeafScript(key);

    // Leaf without timelock
    VaultLeafDescriptor no_timelock;
    no_timelock.script = std::vector<unsigned char>(script.begin(), script.end());
    no_timelock.leaf_version = TAPROOT_LEAF_TAPSCRIPT;
    no_timelock.signing_key = key;
    no_timelock.purpose = "repay";
    no_timelock.timelock = std::nullopt;

    // Serialize + deserialize
    DataStream ss{};
    ss << no_timelock;
    VaultLeafDescriptor deserialized;
    ss >> deserialized;

    BOOST_CHECK(!deserialized.timelock.has_value());

    // Leaf with timelock
    VaultLeafDescriptor with_timelock = no_timelock;
    with_timelock.timelock = 999;

    ss.clear();
    ss << with_timelock;
    VaultLeafDescriptor deserialized2;
    ss >> deserialized2;

    BOOST_CHECK(deserialized2.timelock.has_value());
    BOOST_CHECK_EQUAL(*deserialized2.timelock, 999);
}

// ============================================================================
// VaultBuilder Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(vaultbuilder_basic_two_leaf_tree)
{
    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();

    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key, 12345);

    // Build taproot tree
    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    BOOST_CHECK(builder.IsValid());
    BOOST_CHECK(builder.IsComplete());

    // Create leaf metadata
    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", 12345));

    // Build VaultMetadata
    uint256 contract_id = GetRandHash();
    auto metadata_opt = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);

    BOOST_CHECK(metadata_opt.has_value());
    const VaultMetadata& metadata = *metadata_opt;

    // Verify metadata contents
    BOOST_CHECK_EQUAL(metadata.version, VaultMetadata::CURRENT_VERSION);
    BOOST_CHECK(metadata.contract_id == contract_id);
    BOOST_CHECK(metadata.role == VaultRole::REPO_BORROWER);
    BOOST_CHECK_EQUAL(metadata.leaves.size(), 2);
    BOOST_CHECK(metadata.Validate());

    // Verify spenddata was extracted
    BOOST_CHECK(metadata.spenddata.internal_key == internal_key);
    BOOST_CHECK(!metadata.spenddata.merkle_root.IsNull());
    BOOST_CHECK(!metadata.spenddata.scripts.empty());
}

BOOST_AUTO_TEST_CASE(vaultbuilder_determinism)
{
    // Same inputs should produce identical metadata
    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key, 12345);
    uint256 contract_id = GetRandHash();

    auto build_metadata = [&]() -> VaultMetadata {
        TaprootBuilder builder;
        builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                    TAPROOT_LEAF_TAPSCRIPT, true);
        builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                    TAPROOT_LEAF_TAPSCRIPT, true);
        builder.Finalize(internal_key);

        std::vector<VaultLeafDescriptor> leaves;
        leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", 12345));

        auto meta_opt = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
        BOOST_CHECK(meta_opt.has_value());
        return *meta_opt;
    };

    VaultMetadata meta1 = build_metadata();
    VaultMetadata meta2 = build_metadata();

    // Output keys should be identical (deterministic)
    BOOST_CHECK(meta1.GetOutputKey() == meta2.GetOutputKey());
    BOOST_CHECK(meta1.GetScriptPubKey() == meta2.GetScriptPubKey());
    BOOST_CHECK(meta1.spenddata.merkle_root == meta2.spenddata.merkle_root);
}

BOOST_AUTO_TEST_CASE(vaultbuilder_rejects_invalid_builder)
{
    [[maybe_unused]] XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf_key = CreateTestXOnlyKey();
    CScript leaf_script = CreateTestLeafScript(leaf_key);

    // Incomplete builder (not finalized)
    TaprootBuilder incomplete_builder;
    incomplete_builder.Add(1, std::vector<unsigned char>(leaf_script.begin(), leaf_script.end()),
                           TAPROOT_LEAF_TAPSCRIPT, true);
    // Don't finalize

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf_script, leaf_key, "test", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata_opt = VaultBuilder::Build(incomplete_builder, contract_id, VaultRole::REPO_BORROWER, leaves);

    BOOST_CHECK(!metadata_opt.has_value());
}

BOOST_AUTO_TEST_CASE(vaultbuilder_rejects_mismatched_leaves)
{
    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf3_key = CreateTestXOnlyKey();

    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key);
    CScript leaf3_script = CreateTestLeafScript(leaf3_key);  // Not in tree

    // Build tree with leaf1 and leaf2
    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    // But metadata claims leaf3 exists (which is NOT in the tree)
    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf3_script, leaf3_key, "wrong", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata_opt = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);

    // Should fail - leaf3 not in tree
    BOOST_CHECK(!metadata_opt.has_value());
}

// ============================================================================
// VaultMetadata Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(vault_metadata_validation)
{
    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key);

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(metadata.has_value());

    // Valid metadata
    BOOST_CHECK(metadata->Validate());

    // Invalid: Null contract_id
    VaultMetadata invalid_contract = *metadata;
    invalid_contract.contract_id.SetNull();
    BOOST_CHECK(!invalid_contract.Validate());

    // Invalid: Empty leaves
    VaultMetadata no_leaves = *metadata;
    no_leaves.leaves.clear();
    BOOST_CHECK(!no_leaves.Validate());

    // Invalid: Leaf not in spenddata.scripts
    VaultMetadata extra_leaf = *metadata;
    XOnlyPubKey fake_key = CreateTestXOnlyKey();
    CScript fake_script = CreateTestLeafScript(fake_key);
    extra_leaf.leaves.push_back(VaultBuilder::CreateLeaf(fake_script, fake_key, "fake", std::nullopt));
    BOOST_CHECK(!extra_leaf.Validate());
}

BOOST_AUTO_TEST_CASE(vault_metadata_output_key_caching)
{
    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key);

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(metadata.has_value());

    // First call computes and caches
    XOnlyPubKey output_key1 = metadata->GetOutputKey();
    BOOST_CHECK(metadata->cached_output_key.has_value());

    // Second call uses cache
    XOnlyPubKey output_key2 = metadata->GetOutputKey();
    BOOST_CHECK(output_key1 == output_key2);

    // ScriptPubKey also caches
    CScript spk1 = metadata->GetScriptPubKey();
    BOOST_CHECK(metadata->cached_scriptPubKey.has_value());

    CScript spk2 = metadata->GetScriptPubKey();
    BOOST_CHECK(spk1 == spk2);
}

BOOST_AUTO_TEST_CASE(vault_metadata_serialization_roundtrip)
{
    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();

    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key, 999);

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", 999));

    uint256 contract_id = GetRandHash();
    auto original = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(original.has_value());

    // Serialize
    DataStream ss{};
    ss << *original;

    // Deserialize
    VaultMetadata deserialized;
    ss >> deserialized;

    // Verify all critical fields
    BOOST_CHECK_EQUAL(deserialized.version, original->version);
    BOOST_CHECK(deserialized.contract_id == original->contract_id);
    BOOST_CHECK(deserialized.role == original->role);
    BOOST_CHECK(deserialized.spenddata.internal_key == original->spenddata.internal_key);
    BOOST_CHECK(deserialized.spenddata.merkle_root == original->spenddata.merkle_root);
    BOOST_CHECK_EQUAL(deserialized.leaves.size(), original->leaves.size());

    // Verify it still validates
    BOOST_CHECK(deserialized.Validate());

    // Verify derived values match (caches should be cleared, then recomputed)
    BOOST_CHECK(deserialized.GetOutputKey() == original->GetOutputKey());
    BOOST_CHECK(deserialized.GetScriptPubKey() == original->GetScriptPubKey());
}

// ============================================================================
// VaultRegistry Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(vault_registry_basic_registration)
{
    VaultRegistry registry;

    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key);

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(metadata.has_value());

    // Register
    BOOST_CHECK(registry.RegisterVault(*metadata));
    BOOST_CHECK_EQUAL(registry.Size(), 1);

    // Lookup by output key
    XOnlyPubKey output_key = metadata->GetOutputKey();
    auto found = registry.GetVaultByOutputKey(output_key);
    BOOST_CHECK(found.has_value());
    BOOST_CHECK(found->contract_id == contract_id);

    // Lookup by script
    CScript covenant_spk = metadata->GetScriptPubKey();
    auto found2 = registry.GetVaultByScript(covenant_spk);
    BOOST_CHECK(found2.has_value());
    BOOST_CHECK(found2->contract_id == contract_id);

    // Check IsRegistered
    BOOST_CHECK(registry.IsRegistered(output_key));
    BOOST_CHECK(registry.IsRegistered(covenant_spk));
}

BOOST_AUTO_TEST_CASE(vault_registry_triple_indexing)
{
    VaultRegistry registry;

    uint256 contract_id = GetRandHash();

    // Create 3 vaults for same contract
    for (int i = 0; i < 3; i++) {
        XOnlyPubKey internal_key = CreateTestXOnlyKey();
        XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
        XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
        CScript leaf1_script = CreateTestLeafScript(leaf1_key);
        CScript leaf2_script = CreateTestLeafScript(leaf2_key);

        TaprootBuilder builder;
        builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                    TAPROOT_LEAF_TAPSCRIPT, true);
        builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                    TAPROOT_LEAF_TAPSCRIPT, true);
        builder.Finalize(internal_key);

        std::vector<VaultLeafDescriptor> leaves;
        leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

        auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
        BOOST_REQUIRE(metadata.has_value());
        BOOST_CHECK(registry.RegisterVault(*metadata));
    }

    BOOST_CHECK_EQUAL(registry.Size(), 3);

    // Query by contract_id
    auto contract_vaults = registry.GetContractVaults(contract_id);
    BOOST_CHECK_EQUAL(contract_vaults.size(), 3);

    // All should have same contract_id
    for (const auto& vault : contract_vaults) {
        BOOST_CHECK(vault.contract_id == contract_id);
    }
}

BOOST_AUTO_TEST_CASE(vault_registry_rejects_duplicate)
{
    VaultRegistry registry;

    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key);

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(metadata.has_value());

    // First registration succeeds
    BOOST_CHECK(registry.RegisterVault(*metadata));

    // Duplicate registration fails
    BOOST_CHECK(!registry.RegisterVault(*metadata));
    BOOST_CHECK_EQUAL(registry.Size(), 1);
}

BOOST_AUTO_TEST_CASE(vault_registry_rejects_invalid)
{
    VaultRegistry registry;

    XOnlyPubKey internal_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
    CScript leaf1_script = CreateTestLeafScript(leaf1_key);
    CScript leaf2_script = CreateTestLeafScript(leaf2_key);

    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(internal_key);

    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

    uint256 contract_id = GetRandHash();
    auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(metadata.has_value());

    // Corrupt the metadata (null contract_id)
    VaultMetadata corrupted = *metadata;
    corrupted.contract_id.SetNull();

    // Registration should fail
    BOOST_CHECK(!registry.RegisterVault(corrupted));
    BOOST_CHECK_EQUAL(registry.Size(), 0);
}

BOOST_AUTO_TEST_CASE(vault_registry_xonly_key_cache)
{
    VaultRegistry registry;

    CKey privkey;
    privkey.MakeNewKey(true);
    CPubKey pubkey = privkey.GetPubKey();
    XOnlyPubKey xonly(pubkey);

    // Cache key
    BOOST_CHECK(registry.CacheXOnlyKey(xonly, privkey));

    // Retrieve cached key
    auto cached = registry.GetKeyByXOnly(xonly);
    BOOST_CHECK(cached.has_value());
    BOOST_CHECK(*cached == privkey);

    // Invalid key rejected
    CKey wrong_key;
    wrong_key.MakeNewKey(true);
    BOOST_CHECK(!registry.CacheXOnlyKey(xonly, wrong_key));
}

BOOST_AUTO_TEST_CASE(vault_registry_prune_invalid)
{
    VaultRegistry registry;

    // Add valid vault
    XOnlyPubKey internal_key1 = CreateTestXOnlyKey();
    XOnlyPubKey leaf1a_key = CreateTestXOnlyKey();
    XOnlyPubKey leaf1b_key = CreateTestXOnlyKey();
    CScript leaf1a_script = CreateTestLeafScript(leaf1a_key);
    CScript leaf1b_script = CreateTestLeafScript(leaf1b_key);

    TaprootBuilder builder1;
    builder1.Add(1, std::vector<unsigned char>(leaf1a_script.begin(), leaf1a_script.end()),
                 TAPROOT_LEAF_TAPSCRIPT, true);
    builder1.Add(1, std::vector<unsigned char>(leaf1b_script.begin(), leaf1b_script.end()),
                 TAPROOT_LEAF_TAPSCRIPT, true);
    builder1.Finalize(internal_key1);

    std::vector<VaultLeafDescriptor> leaves1;
    leaves1.push_back(VaultBuilder::CreateLeaf(leaf1a_script, leaf1a_key, "repay", std::nullopt));
    leaves1.push_back(VaultBuilder::CreateLeaf(leaf1b_script, leaf1b_key, "default", std::nullopt));

    uint256 contract_id1 = GetRandHash();
    auto valid_metadata = VaultBuilder::Build(builder1, contract_id1, VaultRole::REPO_BORROWER, leaves1);
    BOOST_REQUIRE(valid_metadata.has_value());
    BOOST_CHECK(registry.RegisterVault(*valid_metadata));

    // Manually add invalid vault (bypass RegisterVault validation)
    // This simulates corrupted DB data
    VaultMetadata invalid_metadata = *valid_metadata;
    invalid_metadata.contract_id.SetNull(); // Make it invalid

    // Direct access to registry internals would be needed here
    // For this test, we'll just verify PruneInvalidVaults doesn't crash
    size_t pruned = registry.PruneInvalidVaults();
    (void)pruned;  // Suppress unused variable warning

    // Should still have the valid vault
    BOOST_CHECK(registry.ValidateVault(valid_metadata->GetOutputKey()));
}

BOOST_AUTO_TEST_CASE(vault_registry_clear)
{
    VaultRegistry registry;

    // Add some vaults
    for (int i = 0; i < 5; i++) {
        XOnlyPubKey internal_key = CreateTestXOnlyKey();
        XOnlyPubKey leaf1_key = CreateTestXOnlyKey();
        XOnlyPubKey leaf2_key = CreateTestXOnlyKey();
        CScript leaf1_script = CreateTestLeafScript(leaf1_key);
        CScript leaf2_script = CreateTestLeafScript(leaf2_key);

        TaprootBuilder builder;
        builder.Add(1, std::vector<unsigned char>(leaf1_script.begin(), leaf1_script.end()),
                    TAPROOT_LEAF_TAPSCRIPT, true);
        builder.Add(1, std::vector<unsigned char>(leaf2_script.begin(), leaf2_script.end()),
                    TAPROOT_LEAF_TAPSCRIPT, true);
        builder.Finalize(internal_key);

        std::vector<VaultLeafDescriptor> leaves;
        leaves.push_back(VaultBuilder::CreateLeaf(leaf1_script, leaf1_key, "repay", std::nullopt));
        leaves.push_back(VaultBuilder::CreateLeaf(leaf2_script, leaf2_key, "default", std::nullopt));

        uint256 contract_id = GetRandHash();
        auto metadata = VaultBuilder::Build(builder, contract_id, VaultRole::REPO_BORROWER, leaves);
        BOOST_REQUIRE(metadata.has_value());
        BOOST_CHECK(registry.RegisterVault(*metadata));
    }

    BOOST_CHECK_EQUAL(registry.Size(), 5);

    // Clear all
    registry.Clear();
    BOOST_CHECK_EQUAL(registry.Size(), 0);
}

// ============================================================================
// Role String Conversion Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(vault_role_to_string)
{
    BOOST_CHECK_EQUAL(VaultRoleToString(VaultRole::REPO_BORROWER), "REPO_BORROWER");
    BOOST_CHECK_EQUAL(VaultRoleToString(VaultRole::REPO_LENDER), "REPO_LENDER");
    BOOST_CHECK_EQUAL(VaultRoleToString(VaultRole::FORWARD_LONG), "FORWARD_LONG");
    BOOST_CHECK_EQUAL(VaultRoleToString(VaultRole::FORWARD_SHORT), "FORWARD_SHORT");
    BOOST_CHECK_EQUAL(VaultRoleToString(VaultRole::FORWARD_ESCROW_B), "FORWARD_ESCROW_B");
    BOOST_CHECK_EQUAL(VaultRoleToString(VaultRole::FORWARD_ESCROW_A), "FORWARD_ESCROW_A");
}

// ============================================================================
// Integration Tests: Full Workflow
// ============================================================================

BOOST_AUTO_TEST_CASE(full_vault_workflow_repo_borrower)
{
    // Simulate complete REPO borrower vault workflow
    VaultRegistry registry;

    // 1. Generate keys
    CKey borrower_privkey;
    borrower_privkey.MakeNewKey(true);
    XOnlyPubKey borrower_key(borrower_privkey.GetPubKey());

    CKey lender_privkey;
    lender_privkey.MakeNewKey(true);
    XOnlyPubKey lender_key(lender_privkey.GetPubKey());

    // 2. Create vault scripts
    CScript repay_script;
    repay_script << std::vector<unsigned char>(borrower_key.begin(), borrower_key.end()) << OP_CHECKSIG;

    CScript default_script;
    default_script << CScriptNum(12345) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    default_script << std::vector<unsigned char>(lender_key.begin(), lender_key.end()) << OP_CHECKSIG;

    // 3. Build taproot tree
    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(repay_script.begin(), repay_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Add(1, std::vector<unsigned char>(default_script.begin(), default_script.end()),
                TAPROOT_LEAF_TAPSCRIPT, true);
    builder.Finalize(borrower_key);

    BOOST_CHECK(builder.IsValid());

    // 4. Create leaf descriptors
    std::vector<VaultLeafDescriptor> leaves;
    leaves.push_back(VaultBuilder::CreateLeaf(repay_script, borrower_key, "repay", std::nullopt));
    leaves.push_back(VaultBuilder::CreateLeaf(default_script, lender_key, "default", 12345));

    // 5. Build metadata
    uint256 offer_id = GetRandHash();
    auto metadata = VaultBuilder::Build(builder, offer_id, VaultRole::REPO_BORROWER, leaves);
    BOOST_REQUIRE(metadata.has_value());

    // 6. Register vault
    BOOST_CHECK(registry.RegisterVault(*metadata));

    // 7. Cache private keys
    BOOST_CHECK(registry.CacheXOnlyKey(borrower_key, borrower_privkey));
    BOOST_CHECK(registry.CacheXOnlyKey(lender_key, lender_privkey));

    // 8. Verify lookup by script
    CScript vault_spk = metadata->GetScriptPubKey();
    auto found = registry.GetVaultByScript(vault_spk);
    BOOST_CHECK(found.has_value());
    BOOST_CHECK(found->role == VaultRole::REPO_BORROWER);

    // 9. Verify we can retrieve keys
    auto borrower_key_cached = registry.GetKeyByXOnly(borrower_key);
    BOOST_CHECK(borrower_key_cached.has_value());
    BOOST_CHECK(*borrower_key_cached == borrower_privkey);

    // 10. Serialize and deserialize (simulating wallet restart)
    DataStream ss{};
    ss << *metadata;

    VaultMetadata reloaded;
    ss >> reloaded;

    BOOST_CHECK(reloaded.Validate());
    BOOST_CHECK(reloaded.GetOutputKey() == metadata->GetOutputKey());

    // 11. Re-register after reload
    VaultRegistry registry2;
    BOOST_CHECK(registry2.RegisterVault(reloaded));

    auto found2 = registry2.GetVaultByScript(vault_spk);
    BOOST_CHECK(found2.has_value());
    BOOST_CHECK(found2->contract_id == offer_id);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
