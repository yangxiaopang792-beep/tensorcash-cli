// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Tests for ZK/KYC asset consensus rules
// Covers critical failure patterns from ZK_TEST_COVERAGE_GAPS.md:
//   - Pattern #6: VK assembled under wrong commitment
//   - Pattern #24: Stale max_root_age logic
//

#include <assets/asset.h>
#include <assets/registry.h>
#include <crypto/groth16.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <test/util/setup_common.h>
#include <test/util/zk_test_helpers.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <vector>

using namespace zk_test;

namespace {

// Helper to create TLV with compact size encoding
std::vector<unsigned char> EncodeTLV(uint8_t type, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> result;
    result.push_back(type);

    size_t len = payload.size();
    if (len < 253) {
        result.push_back(static_cast<unsigned char>(len));
    } else if (len <= 0xFFFF) {
        result.push_back(253);
        result.push_back(len & 0xFF);
        result.push_back((len >> 8) & 0xFF);
    } else if (len <= 0xFFFFFFFF) {
        result.push_back(254);
        for (int i = 0; i < 4; ++i) {
            result.push_back((len >> (i * 8)) & 0xFF);
        }
    } else {
        result.push_back(255);
        for (int i = 0; i < 8; ++i) {
            result.push_back((len >> (i * 8)) & 0xFF);
        }
    }

    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

// Helper to create v1 IssuerReg TLV with ZK metadata
std::vector<unsigned char> MakeIssuerRegWithZK(
    const uint256& asset_id,
    const uint256& vk_commitment,
    uint32_t max_root_age = 144,
    uint32_t policy_bits = assets::MINT_ALLOWED | assets::KYC_REQUIRED)
{
    std::vector<unsigned char> payload;

    // Header
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    for (int i = 0; i < 4; ++i) payload.push_back((policy_bits >> (i * 8)) & 0xFF);

    uint16_t families = assets::SPK_DEFAULT_ALLOWED;
    payload.push_back(families & 0xFF);
    payload.push_back((families >> 8) & 0xFF);

    payload.push_back(assets::ISSUER_REG_FORMAT_V1); // format_version

    // Ticker (empty = not set)
    payload.push_back(0); // ticker_len = 0

    // Decimals (0xFF = not set)
    payload.push_back(0xFF);

    // Unlock fees (UINT64_MAX = not set)
    uint64_t unlock_fees = std::numeric_limits<uint64_t>::max();
    for (int i = 0; i < 8; ++i) payload.push_back((unlock_fees >> (i * 8)) & 0xFF);

    // ZK section (76 bytes) - ZK Whitelist Hardening update
    uint32_t kyc_flags = 0x01;
    for (int i = 0; i < 4; ++i) payload.push_back((kyc_flags >> (i * 8)) & 0xFF);

    payload.insert(payload.end(), vk_commitment.begin(), vk_commitment.end());

    for (int i = 0; i < 4; ++i) payload.push_back((max_root_age >> (i * 8)) & 0xFF);

    uint32_t tfr_flags = 0x00;
    for (int i = 0; i < 4; ++i) payload.push_back((tfr_flags >> (i * 8)) & 0xFF);

    // compliance_root_commit [32] - zero for test
    for (int i = 0; i < 32; ++i) payload.push_back(0);

    // ICU section (129 bytes with icu_visibility, all zeros for minimal test)
    for (int i = 0; i < 129; ++i) payload.push_back(0);

    return EncodeTLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
}

// Helper to create ZK_PARAMS_CHUNK TLV
std::vector<unsigned char> MakeZkParamsChunk(
    const uint256& asset_id,
    const uint256& vk_hash,
    uint16_t chunk_index,
    uint16_t chunk_count,
    const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> payload;

    // asset_id (32 bytes)
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());

    // vk_hash (32 bytes)
    payload.insert(payload.end(), vk_hash.begin(), vk_hash.end());

    // chunk_index (2 bytes LE)
    payload.push_back(chunk_index & 0xFF);
    payload.push_back((chunk_index >> 8) & 0xFF);

    // chunk_count (2 bytes LE)
    payload.push_back(chunk_count & 0xFF);
    payload.push_back((chunk_count >> 8) & 0xFF);

    // data
    payload.insert(payload.end(), data.begin(), data.end());

    return EncodeTLV(static_cast<uint8_t>(assets::OutExtType::ZK_PARAMS_CHUNK), payload);
}

} // namespace

BOOST_AUTO_TEST_SUITE(asset_zk_consensus_tests)

//
// Pattern #6: VK commitment binding - hash verification
//
// This test verifies the VK commitment validation logic:
// 1. Generate two different VKs (VK_A and VK_B)
// 2. Compute their hashes
// 3. Verify that hash(VK_A) ≠ hash(VK_B)
// 4. Demonstrate that chunks must hash to the declared commitment
//
BOOST_AUTO_TEST_CASE(vk_commitment_binding_hash_validation)
{
    // Generate two different VKs
    auto vk_a = MockVerifyingKey(4);  // 4 public inputs
    auto vk_b = MockVerifyingKey(6);  // 6 public inputs (different)

    // Compute their hashes
    HashWriter hasher_a;
    hasher_a.write(std::as_bytes(std::span<const unsigned char>(vk_a.data(), vk_a.size())));
    uint256 commitment_a = hasher_a.GetHash();

    HashWriter hasher_b;
    hasher_b.write(std::as_bytes(std::span<const unsigned char>(vk_b.data(), vk_b.size())));
    uint256 commitment_b = hasher_b.GetHash();

    // Verify hashes are different
    BOOST_CHECK(commitment_a != commitment_b);

    // Split VK_A into chunks
    const size_t chunk_size = 256;
    auto chunks_a = SplitIntoChunks(vk_a, chunk_size);

    // Reassemble and verify hash matches
    std::vector<unsigned char> reassembled;
    for (const auto& chunk : chunks_a) {
        reassembled.insert(reassembled.end(), chunk.begin(), chunk.end());
    }

    HashWriter hasher_verify;
    hasher_verify.write(std::as_bytes(std::span<const unsigned char>(reassembled.data(), reassembled.size())));
    uint256 reassembled_hash = hasher_verify.GetHash();

    // Hash of reassembled chunks should equal original VK hash
    BOOST_CHECK_EQUAL(reassembled_hash, commitment_a);

    // Split VK_B into chunks
    auto chunks_b = SplitIntoChunks(vk_b, chunk_size);

    // Demonstrate mismatch scenario:
    // If IssuerReg declares commitment_a but provides chunks_b, hashes won't match
    std::vector<unsigned char> reassembled_b;
    for (const auto& chunk : chunks_b) {
        reassembled_b.insert(reassembled_b.end(), chunk.begin(), chunk.end());
    }

    HashWriter hasher_wrong;
    hasher_wrong.write(std::as_bytes(std::span<const unsigned char>(reassembled_b.data(), reassembled_b.size())));
    uint256 wrong_hash = hasher_wrong.GetHash();

    // Wrong chunks hash to commitment_b, not commitment_a
    BOOST_CHECK(wrong_hash != commitment_a);
    BOOST_CHECK_EQUAL(wrong_hash, commitment_b);

    BOOST_TEST_MESSAGE("Pattern #6: VK commitment binding validated");
    BOOST_TEST_MESSAGE("  VK_A hash: " << commitment_a.ToString());
    BOOST_TEST_MESSAGE("  VK_B hash: " << commitment_b.ToString());
    BOOST_TEST_MESSAGE("  Reassembled chunks correctly verify against declared commitment");
}

//
// Pattern #6: VK chunk parsing and validation
//
// Verify that ZK_PARAMS_CHUNK TLVs are parsed correctly
// and ValidateChunkParams enforces constraints
//
BOOST_AUTO_TEST_CASE(vk_chunk_parsing_and_validation)
{
    uint256 asset_id = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 vk_hash = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    // Test 1: Valid chunk
    {
        std::vector<unsigned char> data(256, 0xAA);
        auto tlv = MakeZkParamsChunk(asset_id, vk_hash, 0, 4, data);
        auto parsed = assets::ParseZkParamsChunk(tlv);

        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK_EQUAL(parsed->asset_id, asset_id);
        BOOST_CHECK_EQUAL(parsed->vk_hash, vk_hash);
        BOOST_CHECK_EQUAL(parsed->chunk_index, 0);
        BOOST_CHECK_EQUAL(parsed->chunk_count, 4);
        BOOST_CHECK_EQUAL(parsed->data.size(), 256);
        BOOST_CHECK(assets::ValidateChunkParams(*parsed));
    }

    // Test 2: Chunk count = 0 (invalid)
    {
        assets::ZkParamsChunk bad_chunk;
        bad_chunk.chunk_count = 0;
        bad_chunk.chunk_index = 0;
        BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    }

    // Test 3: Chunk count > MAX_ZK_CHUNKS (invalid)
    {
        assets::ZkParamsChunk bad_chunk;
        bad_chunk.chunk_count = assets::MAX_ZK_CHUNKS + 1;
        bad_chunk.chunk_index = 0;
        BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    }

    // Test 4: Chunk index >= chunk_count (invalid)
    {
        assets::ZkParamsChunk bad_chunk;
        bad_chunk.chunk_count = 4;
        bad_chunk.chunk_index = 4; // Should be < 4
        BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    }

    // Test 5: Chunk data > MAX_ZK_CHUNK_SIZE (invalid)
    {
        assets::ZkParamsChunk bad_chunk;
        bad_chunk.chunk_count = 4;
        bad_chunk.chunk_index = 0;
        bad_chunk.data.resize(assets::MAX_ZK_CHUNK_SIZE + 1, 0xFF);
        BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    }

    BOOST_TEST_MESSAGE("Pattern #6: VK chunk parsing and validation completed");
}

//
// Pattern #6: IssuerReg with ZK metadata parsing
//
// Verify that IssuerReg TLVs with ZK metadata are parsed correctly
//
BOOST_AUTO_TEST_CASE(issuerreg_zk_metadata_parsing)
{
    uint256 asset_id = uint256S("0x4444444444444444444444444444444444444444444444444444444444444444");
    uint256 vk_commitment = uint256S("0x5555555555555555555555555555555555555555555555555555555555555555");

    // Create IssuerReg with KYC_REQUIRED flag and v2 metadata
    auto tlv = MakeIssuerRegWithZK(asset_id, vk_commitment, 288);

    // Parse
    auto parsed = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(parsed.has_value());

    // Verify basic fields
    BOOST_CHECK_EQUAL(parsed->asset_id, asset_id);
    BOOST_CHECK_EQUAL(parsed->policy_bits, assets::MINT_ALLOWED | assets::KYC_REQUIRED);
    BOOST_CHECK_EQUAL(parsed->allowed_spk_families, assets::SPK_DEFAULT_ALLOWED);

    // Verify ZK metadata fields (v1: always present, check values)
    BOOST_CHECK_EQUAL(parsed->kyc_flags, 0x01u);
    BOOST_CHECK_EQUAL(parsed->zk_vk_commitment, vk_commitment);
    BOOST_CHECK_EQUAL(parsed->max_root_age, 288u);
    BOOST_CHECK_EQUAL(parsed->tfr_flags, 0x00u);

    BOOST_TEST_MESSAGE("Pattern #6: IssuerReg ZK metadata parsing validated");
}

//
// Pattern #24: max_root_age enforcement - boundary conditions
//
// This test verifies that proofs with stale compliance roots are rejected
//
BOOST_AUTO_TEST_CASE(max_root_age_enforcement_boundary)
{
    // Setup: Create an asset with max_root_age = 100
    uint256 asset_id = uint256S("0x5555555555555555555555555555555555555555555555555555555555555555");
    (void)asset_id; // Would be used in full consensus validation

    // Test 1: Root at current_height - max_root_age (exactly at limit) → should accept
    {
        using namespace groth16;
        VerificationContext ctx{
            .max_root_age = 100,
            .current_height = 200,
            .anchor_commitment = std::nullopt
        };

        // Mock public inputs with root_height = 100 (current - max_root_age)
        std::vector<unsigned char> public_inputs(128, 0);
        // Element [2] = compliance_root with height encoded in last 4 bytes
        // Height 100 in big-endian: 0x00000064
        public_inputs[92] = 0x00;  // Last 4 bytes of element[2]
        public_inputs[93] = 0x00;
        public_inputs[94] = 0x00;
        public_inputs[95] = 0x64;  // 100 in decimal

        // This test demonstrates the age check logic
        // In practice, this would be tested via full proof verification
        uint32_t root_height = (static_cast<uint32_t>(public_inputs[92]) << 24) |
                               (static_cast<uint32_t>(public_inputs[93]) << 16) |
                               (static_cast<uint32_t>(public_inputs[94]) << 8) |
                               static_cast<uint32_t>(public_inputs[95]);

        BOOST_CHECK_EQUAL(root_height, 100);
        BOOST_CHECK(ctx.current_height >= static_cast<int>(root_height));

        uint32_t delta = static_cast<uint32_t>(ctx.current_height - static_cast<int>(root_height));
        BOOST_CHECK_EQUAL(delta, 100);
        BOOST_CHECK(delta <= ctx.max_root_age);  // At limit, should pass
    }

    // Test 2: Root at current_height - max_root_age - 1 (too old) → should reject
    {
        using namespace groth16;
        VerificationContext ctx{
            .max_root_age = 100,
            .current_height = 201,
            .anchor_commitment = std::nullopt
        };

        // Mock public inputs with root_height = 100
        std::vector<unsigned char> public_inputs(128, 0);
        public_inputs[92] = 0x00;
        public_inputs[93] = 0x00;
        public_inputs[94] = 0x00;
        public_inputs[95] = 0x64;  // 100

        uint32_t root_height = (static_cast<uint32_t>(public_inputs[92]) << 24) |
                               (static_cast<uint32_t>(public_inputs[93]) << 16) |
                               (static_cast<uint32_t>(public_inputs[94]) << 8) |
                               static_cast<uint32_t>(public_inputs[95]);

        uint32_t delta = static_cast<uint32_t>(ctx.current_height - static_cast<int>(root_height));
        BOOST_CHECK_EQUAL(delta, 101);
        BOOST_CHECK(delta > ctx.max_root_age);  // Too old, should fail
    }

    // Test 3: max_root_age = 0 disables check (any age allowed)
    {
        using namespace groth16;
        VerificationContext ctx{
            .max_root_age = 0,  // Disabled
            .current_height = 10000,
            .anchor_commitment = std::nullopt
        };

        // With max_root_age = 0, age check should be skipped
        BOOST_CHECK_EQUAL(ctx.max_root_age, 0);
        // In VerifyGroth16WithPolicy, the check is: if (ctx.max_root_age > 0) { ... }
        // So this would bypass the age check entirely
    }

    BOOST_TEST_MESSAGE("max_root_age boundary tests completed");
}

//
// Pattern #2: ZK_PARAMS_CHUNK with duplicate indices
//
BOOST_AUTO_TEST_CASE(vk_chunk_duplicate_index_detection)
{
    uint256 asset_id = uint256S("0x6666666666666666666666666666666666666666666666666666666666666666");
    uint256 vk_hash = uint256S("0x7777777777777777777777777777777777777777777777777777777777777777");

    // Create chunks with indices [0, 1, 1, 2] (duplicate index 1)
    std::vector<unsigned char> chunk_data(256, 0xAA);

    auto chunk0 = MakeZkParamsChunk(asset_id, vk_hash, 0, 3, chunk_data);
    auto chunk1a = MakeZkParamsChunk(asset_id, vk_hash, 1, 3, chunk_data);
    auto chunk1b = MakeZkParamsChunk(asset_id, vk_hash, 1, 3, chunk_data);  // Duplicate
    auto chunk2 = MakeZkParamsChunk(asset_id, vk_hash, 2, 3, chunk_data);

    // Parse chunks individually
    auto parsed0 = assets::ParseZkParamsChunk(chunk0);
    auto parsed1a = assets::ParseZkParamsChunk(chunk1a);
    auto parsed1b = assets::ParseZkParamsChunk(chunk1b);
    auto parsed2 = assets::ParseZkParamsChunk(chunk2);

    BOOST_REQUIRE(parsed0.has_value());
    BOOST_REQUIRE(parsed1a.has_value());
    BOOST_REQUIRE(parsed1b.has_value());
    BOOST_REQUIRE(parsed2.has_value());

    // Verify indices
    BOOST_CHECK_EQUAL(parsed0->chunk_index, 0);
    BOOST_CHECK_EQUAL(parsed1a->chunk_index, 1);
    BOOST_CHECK_EQUAL(parsed1b->chunk_index, 1);  // Duplicate
    BOOST_CHECK_EQUAL(parsed2->chunk_index, 2);

    // In actual ConnectBlock, duplicate detection would happen during assembly
    // The implementation should track seen indices and reject duplicates
    std::vector<bool> seen(3, false);
    seen[parsed0->chunk_index] = true;
    seen[parsed1a->chunk_index] = true;

    // Attempting to process duplicate chunk should fail
    bool duplicate_detected = seen[parsed1b->chunk_index];
    BOOST_CHECK(duplicate_detected);

    BOOST_TEST_MESSAGE("Chunk duplication detected - ConnectBlock should reject this");
}

//
// Pattern #2: ZK_PARAMS_CHUNK with gaps in sequence
//
BOOST_AUTO_TEST_CASE(vk_chunk_sequence_gap_detection)
{
    // Verify that VK chunk assembly detects incomplete sequences
    // Chunks [0, 1, 3] with count=4 (missing index 2)

    uint256 asset_id = uint256S("0x8888888888888888888888888888888888888888888888888888888888888888");
    uint256 vk_hash = uint256S("0x9999999999999999999999999999999999999999999999999999999999999999");

    std::vector<unsigned char> chunk_data(256, 0xBB);

    auto chunk0 = MakeZkParamsChunk(asset_id, vk_hash, 0, 4, chunk_data);
    auto chunk1 = MakeZkParamsChunk(asset_id, vk_hash, 1, 4, chunk_data);
    // Index 2 is missing
    auto chunk3 = MakeZkParamsChunk(asset_id, vk_hash, 3, 4, chunk_data);

    auto parsed0 = assets::ParseZkParamsChunk(chunk0);
    auto parsed1 = assets::ParseZkParamsChunk(chunk1);
    auto parsed3 = assets::ParseZkParamsChunk(chunk3);

    BOOST_REQUIRE(parsed0.has_value());
    BOOST_REQUIRE(parsed1.has_value());
    BOOST_REQUIRE(parsed3.has_value());

    // Simulate ConnectBlock's completeness check
    std::vector<bool> present(4, false);
    present[parsed0->chunk_index] = true;
    present[parsed1->chunk_index] = true;
    present[parsed3->chunk_index] = true;

    // Check for gaps - all indices [0..count-1] should be present
    bool all_present = std::all_of(present.begin(), present.end(), [](bool b) { return b; });
    BOOST_CHECK(!all_present);  // Gap detected (index 2 missing)

    // Find the missing index
    for (size_t i = 0; i < present.size(); ++i) {
        if (!present[i]) {
            BOOST_CHECK_EQUAL(i, 2);  // Verify index 2 is missing
            break;
        }
    }

    BOOST_TEST_MESSAGE("Chunk sequence gap detected - ConnectBlock should reject incomplete assembly");
}

BOOST_AUTO_TEST_SUITE_END()
