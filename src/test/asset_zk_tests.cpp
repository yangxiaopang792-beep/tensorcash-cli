#include <assets/asset.h>
#include <assets/registry.h>
#include <crypto/groth16.h>
#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <protocol.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <array>
#include <string>
#include <vector>

namespace {

// Helper to build v1 IssuerReg (format_version=1, always includes ZK+ICU sections)
std::vector<unsigned char> MakeIssuerRegV1(const uint256& asset_id,
                                            uint32_t policy_bits,
                                            uint16_t allowed_spk,
                                            const std::string& ticker = "",
                                            uint8_t decimals = 0xFF,
                                            uint64_t unlock_fees = std::numeric_limits<uint64_t>::max(),
                                            uint32_t kyc_flags = 0,
                                            const uint256& vk_commitment = uint256(),
                                            uint32_t max_root_age = 0,
                                            uint32_t tfr_flags = 0)
{
    std::vector<unsigned char> payload;

    // Header
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char buf32[4]; WriteLE32(buf32, policy_bits); payload.insert(payload.end(), buf32, buf32+4);
    unsigned char buf16[2]; WriteLE16(buf16, allowed_spk); payload.insert(payload.end(), buf16, buf16+2);
    payload.push_back(assets::ISSUER_REG_FORMAT_V1); // format_version

    // Ticker
    payload.push_back(static_cast<uint8_t>(ticker.size()));
    payload.insert(payload.end(), ticker.begin(), ticker.end());

    // Decimals
    payload.push_back(decimals);

    // Unlock fees
    unsigned char buf64[8]; WriteLE64(buf64, unlock_fees); payload.insert(payload.end(), buf64, buf64+8);

    // ZK section (76 bytes) - ZK Whitelist Hardening update
    WriteLE32(buf32, kyc_flags); payload.insert(payload.end(), buf32, buf32+4);
    payload.insert(payload.end(), vk_commitment.begin(), vk_commitment.end());
    WriteLE32(buf32, max_root_age); payload.insert(payload.end(), buf32, buf32+4);
    WriteLE32(buf32, tfr_flags); payload.insert(payload.end(), buf32, buf32+4);
    // compliance_root_commit [32] - zero for test
    payload.insert(payload.end(), 32, 0);

    // ICU section (129 bytes with icu_visibility, all zeros for minimal test)
    for (int i = 0; i < 129; ++i) payload.push_back(0);

    // Wrap in TLV
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ISSUER_REG));
    if (payload.size() < 253) {
        tlv.push_back(static_cast<unsigned char>(payload.size()));
    } else {
        tlv.push_back(253);
        tlv.push_back(payload.size() & 0xFF);
        tlv.push_back((payload.size() >> 8) & 0xFF);
    }
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::vector<unsigned char> MakeChunkTlv(uint16_t chunk_index, uint16_t chunk_count, const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), 32, 0x33);
    payload.insert(payload.end(), 32, 0x44);
    unsigned char buf16[2];
    WriteLE16(buf16, chunk_index);
    payload.insert(payload.end(), buf16, buf16 + 2);
    WriteLE16(buf16, chunk_count);
    payload.insert(payload.end(), buf16, buf16 + 2);
    payload.insert(payload.end(), data.begin(), data.end());

    std::vector<unsigned char> tlv;
    tlv.reserve(payload.size() + 10);
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ZK_PARAMS_CHUNK));
    const size_t len = payload.size();
    if (len < 253) {
        tlv.push_back(static_cast<unsigned char>(len));
    } else if (len <= std::numeric_limits<uint16_t>::max()) {
        tlv.push_back(253);
        unsigned char buf[2];
        WriteLE16(buf, len);
        tlv.insert(tlv.end(), buf, buf + 2);
    } else if (len <= std::numeric_limits<uint32_t>::max()) {
        tlv.push_back(254);
        unsigned char buf[4];
        WriteLE32(buf, static_cast<uint32_t>(len));
        tlv.insert(tlv.end(), buf, buf + 4);
    } else {
        tlv.push_back(255);
        unsigned char buf[8];
        WriteLE64(buf, static_cast<uint64_t>(len));
        tlv.insert(tlv.end(), buf, buf + 8);
    }
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::vector<unsigned char> MakeAnchorTlv(const std::vector<unsigned char>& locator)
{
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), 32, 0x55);
    payload.insert(payload.end(), 32, 0x66);
    unsigned char buf32[4];
    WriteLE32(buf32, 7);
    payload.insert(payload.end(), buf32, buf32 + 4);
    payload.insert(payload.end(), locator.begin(), locator.end());

    std::vector<unsigned char> tlv;
    tlv.reserve(payload.size() + 2);
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::TFR_ANCHOR));
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

} // namespace

BOOST_AUTO_TEST_SUITE(asset_zk_tests)

BOOST_AUTO_TEST_CASE(parse_issuerreg_v1_lengths)
{
    // Minimal v1: no ticker, no unlock_fees (sentinels)
    uint256 asset_id1;
    memset(asset_id1.data(), 0x11, asset_id1.size());
    auto tlv = MakeIssuerRegV1(asset_id1,
                               assets::MINT_ALLOWED | assets::BURN_ALLOWED,
                               assets::SPK_DEFAULT_ALLOWED,
                               /*ticker=*/"",
                               /*decimals=*/0xFF,
                               /*unlock_fees=*/std::numeric_limits<uint64_t>::max());
    auto parsed = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(parsed);
    BOOST_CHECK_EQUAL(parsed->kyc_flags, 0u); // ZK section present but zeroed
    BOOST_CHECK(parsed->zk_vk_commitment.IsNull());
    BOOST_CHECK_EQUAL(parsed->allowed_spk_families, assets::SPK_DEFAULT_ALLOWED);
    BOOST_CHECK(parsed->ticker.empty()); // not set
    BOOST_CHECK_EQUAL(parsed->decimals, 0xFF); // not set

    // With unlock + ticker + decimals
    uint256 asset_id2;
    memset(asset_id2.data(), 0x22, asset_id2.size());
    tlv = MakeIssuerRegV1(asset_id2,
                          assets::MINT_ALLOWED,
                          assets::SPK_DEFAULT_ALLOWED,
                          /*ticker=*/"GOLD",
                          /*decimals=*/8,
                          /*unlock_fees=*/1'000'000);
    parsed = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(parsed);
    BOOST_CHECK_EQUAL(parsed->ticker, "GOLD");
    BOOST_CHECK_EQUAL(parsed->decimals, 8);
    BOOST_CHECK_EQUAL(parsed->unlock_fees_sats, 1'000'000u);
    BOOST_CHECK_EQUAL(parsed->kyc_flags, 0u); // ZK section present but zeroed
}

BOOST_AUTO_TEST_CASE(parse_issuerreg_v1_with_zk_populated)
{
    // v1 format with ZK section populated (KYC+TFR flags set)
    uint256 asset_id;
    memset(asset_id.data(), 0x33, asset_id.size());

    uint256 vk_commit;
    memset(vk_commit.data(), 0x77, vk_commit.size());

    auto tlv = MakeIssuerRegV1(asset_id,
                               assets::MINT_ALLOWED | assets::KYC_REQUIRED | assets::TFR_ANCHOR_REQUIRED,
                               assets::SPK_DEFAULT_ALLOWED,
                               /*ticker=*/"KYC",
                               /*decimals=*/0xFF,
                               /*unlock_fees=*/2'000'000,
                               /*kyc_flags=*/0x01u,
                               /*vk_commitment=*/vk_commit,
                               /*max_root_age=*/144u,
                               /*tfr_flags=*/0x02u);

    auto parsed = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(parsed);
    BOOST_CHECK_EQUAL(parsed->kyc_flags, 0x01u);
    BOOST_CHECK(parsed->zk_vk_commitment == vk_commit);
    BOOST_CHECK_EQUAL(parsed->max_root_age, 144u);
    BOOST_CHECK_EQUAL(parsed->tfr_flags, 0x02u);
    BOOST_CHECK_EQUAL(parsed->ticker, "KYC");
    BOOST_CHECK_EQUAL(parsed->unlock_fees_sats, 2'000'000u);
    BOOST_CHECK_EQUAL(parsed->format_version, assets::ISSUER_REG_FORMAT_V1);
}

BOOST_AUTO_TEST_CASE(parse_zk_chunk_and_helper)
{
    auto tlv = MakeChunkTlv(/*chunk_index=*/1, /*chunk_count=*/4, std::vector<unsigned char>(100, 0xAA));
    auto parsed = assets::ParseZkParamsChunk(tlv);
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(assets::ValidateChunkParams(*parsed));

    assets::ZkParamsChunk bad_chunk = *parsed;
    bad_chunk.chunk_count = 0;
    BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    bad_chunk.chunk_count = 9;
    BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    bad_chunk.chunk_count = parsed->chunk_count;
    bad_chunk.chunk_index = bad_chunk.chunk_count;
    BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
    bad_chunk.chunk_index = 0;
    bad_chunk.data.resize(assets::MAX_ZK_CHUNK_SIZE + 1);
    BOOST_CHECK(!assets::ValidateChunkParams(bad_chunk));
}

BOOST_AUTO_TEST_CASE(vk_chunk_hash_roundtrip)
{
    constexpr uint16_t chunk_count = 3;
    std::array<std::vector<unsigned char>, chunk_count> parts{
        std::vector<unsigned char>(128, 0x01),
        std::vector<unsigned char>(256, 0x02),
        std::vector<unsigned char>(96, 0x03)};

    HashWriter builder;
    for (const auto& part : parts) {
        builder.write(std::as_bytes(std::span<const unsigned char>(part.data(), part.size())));
    }
    const uint256 commitment = builder.GetHash();

    std::vector<std::vector<unsigned char>> reassembled(chunk_count);
    std::vector<bool> seen(chunk_count, false);
    size_t total = 0;
    for (uint16_t idx = 0; idx < chunk_count; ++idx) {
        auto tlv = MakeChunkTlv(idx, chunk_count, parts[idx]);
        auto parsed = assets::ParseZkParamsChunk(tlv);
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(assets::ValidateChunkParams(*parsed));
        BOOST_CHECK_EQUAL(parsed->chunk_index, idx);
        BOOST_CHECK_EQUAL(parsed->chunk_count, chunk_count);
        seen[idx] = true;
        reassembled[idx] = parsed->data;
        total += parsed->data.size();
    }
    BOOST_CHECK(std::all_of(seen.begin(), seen.end(), [](bool b){ return b; }));
    BOOST_CHECK(total <= assets::MAX_VK_PAYLOAD_SIZE);

    HashWriter verify;
    for (uint16_t idx = 0; idx < chunk_count; ++idx) {
        verify.write(std::as_bytes(std::span<const unsigned char>(reassembled[idx].data(), reassembled[idx].size())));
    }
    BOOST_CHECK(verify.GetHash() == commitment);
}

BOOST_AUTO_TEST_CASE(groth16_verifier_failure_paths)
{
    using namespace groth16;

    VerificationContext ctx{.max_root_age = 0, .current_height = 0, .anchor_commitment = std::nullopt};
    std::vector<unsigned char> empty;

    // Invalid verifying key length
    VerifyError err = VerifyGroth16WithPolicy(std::span<const unsigned char>(empty), std::span<const unsigned char>(empty), std::span<const unsigned char>(empty), ctx);
    BOOST_CHECK(err == VerifyError::InvalidVerifyingKey);

    // Create minimal VK header with incorrect length causing failure during parsing
    std::vector<unsigned char> vk_bytes(2, 0x00); // gamma count zero but missing elements
    err = VerifyGroth16WithPolicy(std::span<const unsigned char>(empty), std::span<const unsigned char>(empty), std::span<const unsigned char>(vk_bytes), ctx);
    BOOST_CHECK(err == VerifyError::InvalidVerifyingKey);
}

BOOST_AUTO_TEST_CASE(parse_tfr_anchor)
{
    auto tlv = MakeAnchorTlv(std::vector<unsigned char>(32, 0xAB));
    auto parsed = assets::ParseTfrAnchor(tlv);
    BOOST_REQUIRE(parsed);
    BOOST_CHECK_EQUAL(parsed->locator.size(), 32u);
    BOOST_CHECK_EQUAL(parsed->keyset_id, 7u);
}

BOOST_AUTO_TEST_CASE(asset_registry_serialization_defaults_and_ext)
{
    AssetRegistryEntry entry;
    entry.policy_bits = 0x1234u;
    entry.allowed_spk_families = 0x0005u;
    entry.unlock_fees_sats = 5000;
    entry.fees_accum_sats = 100;
    entry.rotation_min_sats = 200;
    entry.ticker = "USD";
    entry.decimals = 2;

    DataStream ss_legacy;
    ss_legacy << entry.policy_bits << entry.allowed_spk_families << entry.icu_outpoint << entry.unlock_fees_sats
              << entry.fees_accum_sats << entry.rotation_min_sats << entry.ticker << entry.decimals;

    AssetRegistryEntry legacy_read;
    ss_legacy >> legacy_read;
    BOOST_CHECK(!legacy_read.has_kyc);
    BOOST_CHECK(legacy_read.zk_vk_commitment.IsNull());
    BOOST_CHECK_EQUAL(legacy_read.max_root_age, 0u);
    BOOST_CHECK_EQUAL(legacy_read.tfr_flags, 0u);

    auto vk = uint256::FromHex(std::string(64, 'A'));
    BOOST_REQUIRE(vk);

    AssetRegistryEntry extended = entry;
    extended.has_kyc = true;
    extended.zk_vk_commitment = *vk;
    extended.max_root_age = 288;
    extended.tfr_flags = 0x03u;

    DataStream ss;
    ss << extended;
    AssetRegistryEntry roundtrip;
    ss >> roundtrip;

    BOOST_CHECK(roundtrip.has_kyc);
    BOOST_CHECK(roundtrip.zk_vk_commitment == *vk);
    BOOST_CHECK_EQUAL(roundtrip.max_root_age, 288u);
    BOOST_CHECK_EQUAL(roundtrip.tfr_flags, 0x03u);
}

BOOST_AUTO_TEST_SUITE_END()
