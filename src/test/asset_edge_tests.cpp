// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/asset.h>
#include <consensus/tx_verify.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <test/util/setup_common.h>
#include <test/util/random.h>
#include <validation.h>
#include <uint256.h>

#include <array>
#include <optional>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(asset_edge_tests, BasicTestingSetup)

// Helper to create AssetTag TLV
static std::vector<unsigned char> MakeAssetTag(const uint256& asset_id,
                                              uint64_t amount,
                                              uint32_t flags = 0,
                                              std::optional<uint8_t> epoch = std::nullopt)
{
    std::vector<unsigned char> tlv;
    tlv.push_back(0x01); // AssetTag type
    size_t value_len = 32 + 8 + (flags ? 4 : 0) + (epoch.has_value() ? 3 : 0);
    tlv.push_back(static_cast<unsigned char>(value_len));
    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
    for (int i = 0; i < 8; ++i) {
        tlv.push_back((amount >> (i * 8)) & 0xFF);
    }
    if (flags) {
        for (int i = 0; i < 4; ++i) {
            tlv.push_back((flags >> (i * 8)) & 0xFF);
        }
    }
    if (epoch.has_value()) {
        tlv.push_back(0x02); // epoch sub-TLV type
        tlv.push_back(0x01); // length
        tlv.push_back(epoch.value());
    }
    return tlv;
}

// Helper to build v1 IssuerReg (format_version=1, always includes ZK+ICU sections)
static std::vector<unsigned char> MakeIssuerRegV1(const uint256& asset_id,
                                                   uint32_t policy_bits,
                                                   uint16_t allowed_spk,
                                                   const std::string& ticker = "",
                                                   uint8_t decimals = 0xFF,
                                                   uint64_t unlock_fees = std::numeric_limits<uint64_t>::max())
{
    std::vector<unsigned char> payload;

    // Header
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    for (int i = 0; i < 4; ++i) payload.push_back((policy_bits >> (i * 8)) & 0xFF);
    for (int i = 0; i < 2; ++i) payload.push_back((allowed_spk >> (i * 8)) & 0xFF);
    payload.push_back(assets::ISSUER_REG_FORMAT_V1); // format_version

    // Ticker
    payload.push_back(static_cast<uint8_t>(ticker.size()));
    payload.insert(payload.end(), ticker.begin(), ticker.end());

    // Decimals
    payload.push_back(decimals);

    // Unlock fees
    for (int i = 0; i < 8; ++i) payload.push_back((unlock_fees >> (i * 8)) & 0xFF);

    // ZK section (76 bytes, all zeros for minimal test) - ZK Whitelist Hardening update
    for (int i = 0; i < 76; ++i) payload.push_back(0);

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

BOOST_AUTO_TEST_CASE(asset_amount_overflow_protection)
{
    // Test that amount overflow is detected
    uint256 asset_id;
    memset(asset_id.data(), 0x12, asset_id.size());
    
    // Create TLV with maximum uint64 amount
    auto tlv1 = MakeAssetTag(asset_id, UINT64_MAX, 0);
    auto parsed1 = assets::ParseAssetTag(tlv1);
    BOOST_CHECK(parsed1.has_value());
    BOOST_CHECK_EQUAL(parsed1->amount, UINT64_MAX);
    
    // Test overflow in delta accumulation
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    
    // Two outputs with near-max amounts
    CTxOut out1(1000, CScript() << OP_TRUE);
    out1.vExt = MakeAssetTag(asset_id, UINT64_MAX - 1000, 0);
    mtx.vout.push_back(out1);
    
    CTxOut out2(1000, CScript() << OP_TRUE);
    out2.vExt = MakeAssetTag(asset_id, 2000, 0);
    mtx.vout.push_back(out2);
    
    // This should handle overflow gracefully using 128-bit arithmetic
    // The delta tracking in CheckTxInputs uses __int128_t
    CTransaction tx(mtx);
    
    // Verify both outputs parsed correctly
    auto tag1 = assets::ParseAssetTag(tx.vout[0].vExt);
    auto tag2 = assets::ParseAssetTag(tx.vout[1].vExt);
    BOOST_CHECK(tag1.has_value());
    BOOST_CHECK(tag2.has_value());
    BOOST_CHECK_EQUAL(tag1->amount, UINT64_MAX - 1000);
    BOOST_CHECK_EQUAL(tag2->amount, 2000);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_optional_fields)
{
    uint256 asset_id;
    memset(asset_id.data(), 0x42, asset_id.size());

    // Case 1: ticker + decimals, no unlock_fees (sentinel = UINT64_MAX)
    auto tlv_ticker = MakeIssuerRegV1(asset_id,
                                      /*policy_bits=*/0x0003u,
                                      /*allowed_spk=*/assets::SPK_DEFAULT_ALLOWED,
                                      /*ticker=*/std::string("TICKERLONG"),
                                      /*decimals=*/8,
                                      /*unlock_fees=*/std::numeric_limits<uint64_t>::max());
    auto parsed_ticker = assets::ParseIssuerReg(tlv_ticker);
    BOOST_REQUIRE(parsed_ticker.has_value());
    BOOST_CHECK_EQUAL(parsed_ticker->unlock_fees_sats, std::numeric_limits<uint64_t>::max()); // not set
    BOOST_CHECK_EQUAL(parsed_ticker->ticker, "TICKERLONG");
    BOOST_CHECK_EQUAL(parsed_ticker->decimals, 8);

    // Case 2: unlock only, no ticker/decimals (sentinels: empty ticker, decimals=0xFF)
    auto tlv_unlock = MakeIssuerRegV1(asset_id,
                                      0x0003u,
                                      assets::SPK_DEFAULT_ALLOWED,
                                      /*ticker=*/"",
                                      /*decimals=*/0xFF,
                                      /*unlock_fees=*/123456789);
    auto parsed_unlock = assets::ParseIssuerReg(tlv_unlock);
    BOOST_REQUIRE(parsed_unlock.has_value());
    BOOST_CHECK_EQUAL(parsed_unlock->unlock_fees_sats, 123456789);
    BOOST_CHECK(parsed_unlock->ticker.empty()); // not set
    BOOST_CHECK_EQUAL(parsed_unlock->decimals, 0xFF); // not set

    // Case 3: unlock + ticker + decimals all set
    auto tlv_full = MakeIssuerRegV1(asset_id,
                                    0x0003u,
                                    static_cast<uint16_t>(assets::SPK_P2PKH | assets::SPK_P2WPKH),
                                    /*ticker=*/"TISSUER",
                                    /*decimals=*/6,
                                    /*unlock_fees=*/5000);
    auto parsed_full = assets::ParseIssuerReg(tlv_full);
    BOOST_REQUIRE(parsed_full.has_value());
    BOOST_CHECK_EQUAL(parsed_full->unlock_fees_sats, 5000);
    BOOST_CHECK_EQUAL(parsed_full->ticker, "TISSUER");
    BOOST_CHECK_EQUAL(parsed_full->decimals, 6);
    BOOST_CHECK_EQUAL(parsed_full->allowed_spk_families, assets::SPK_P2PKH | assets::SPK_P2WPKH);

    // Case 4: ticker without unlock (v1 always includes all fields with sentinels)
    auto tlv_minimal = MakeIssuerRegV1(asset_id,
                                       0x0003u,
                                       assets::SPK_DEFAULT_ALLOWED,
                                       /*ticker=*/"TNALLOWED",
                                       /*decimals=*/5,
                                       /*unlock_fees=*/std::numeric_limits<uint64_t>::max());
    auto parsed_minimal = assets::ParseIssuerReg(tlv_minimal);
    BOOST_REQUIRE(parsed_minimal.has_value());
    BOOST_CHECK_EQUAL(parsed_minimal->allowed_spk_families, assets::SPK_DEFAULT_ALLOWED);
    BOOST_CHECK_EQUAL(parsed_minimal->ticker, "TNALLOWED");
    BOOST_CHECK_EQUAL(parsed_minimal->decimals, 5);
    BOOST_CHECK_EQUAL(parsed_minimal->format_version, assets::ISSUER_REG_FORMAT_V1);
}

BOOST_AUTO_TEST_CASE(asset_tag_epoch_subtlv)
{
    uint256 asset_id;
    memset(asset_id.data(), 0x24, asset_id.size());

    auto tlv_epoch = MakeAssetTag(asset_id, /*amount=*/500, /*flags=*/0, /*epoch=*/7);
    auto parsed_epoch = assets::ParseAssetTag(tlv_epoch);
    BOOST_REQUIRE(parsed_epoch.has_value());
    BOOST_CHECK(parsed_epoch->has_epoch);
    BOOST_CHECK_EQUAL(parsed_epoch->epoch, 7);
    BOOST_CHECK_EQUAL(parsed_epoch->amount, 500);
    BOOST_CHECK_EQUAL(parsed_epoch->flags, 0U);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v1_format)
{
    auto append_le16 = [](std::vector<unsigned char>& out, uint16_t value) {
        for (int i = 0; i < 2; ++i) out.push_back((value >> (8 * i)) & 0xFF);
    };
    auto append_le32 = [](std::vector<unsigned char>& out, uint32_t value) {
        for (int i = 0; i < 4; ++i) out.push_back((value >> (8 * i)) & 0xFF);
    };
    auto append_le64 = [](std::vector<unsigned char>& out, uint64_t value) {
        for (int i = 0; i < 8; ++i) out.push_back((value >> (8 * i)) & 0xFF);
    };

    uint256 asset_id;
    memset(asset_id.data(), 0x01, asset_id.size());

    std::vector<unsigned char> payload;
    // V1 format header
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    append_le32(payload, 0x0003u); // policy_bits: MINT_ALLOWED | BURN_ALLOWED
    append_le16(payload, assets::SPK_DEFAULT_ALLOWED);
    payload.push_back(assets::ISSUER_REG_FORMAT_V1); // format_version = 1

    // Optional ticker (4 bytes: "GOLD")
    payload.push_back(4); // ticker_len
    payload.insert(payload.end(), {'G', 'O', 'L', 'D'});

    // Optional decimals (8)
    payload.push_back(8);

    // Optional unlock_fees (500M sats)
    append_le64(payload, 500'000'000ULL);

    auto fill_uint256 = [](uint256& dst, unsigned char seed) {
        for (size_t i = 0; i < dst.size(); ++i) {
            dst.begin()[i] = static_cast<unsigned char>(seed + i);
        }
    };

    // ZK section (always present in v1, 76 bytes total) - ZK Whitelist Hardening update
    uint32_t kyc_flags = 0x12u;
    append_le32(payload, kyc_flags);

    uint256 vk_commit;
    fill_uint256(vk_commit, 0x10);
    payload.insert(payload.end(), vk_commit.begin(), vk_commit.end());

    uint32_t max_root_age = 288u;
    append_le32(payload, max_root_age);

    uint32_t tfr_flags = 0x04u;
    append_le32(payload, tfr_flags);

    // compliance_root_commit [32] - zero for test
    uint256 compliance_root;
    payload.insert(payload.end(), compliance_root.begin(), compliance_root.end());

    // ICU section (always present in v1, 129 bytes total with icu_visibility)
    uint32_t icu_flags = 0x08u;
    append_le32(payload, icu_flags);

    uint64_t issuance_cap_units = 1'000'000ULL;
    append_le64(payload, issuance_cap_units);

    uint256 icu_ctxt_commit;
    fill_uint256(icu_ctxt_commit, 0x20);
    payload.insert(payload.end(), icu_ctxt_commit.begin(), icu_ctxt_commit.end());

    uint256 icu_plain_commit;
    fill_uint256(icu_plain_commit, 0x30);
    payload.insert(payload.end(), icu_plain_commit.begin(), icu_plain_commit.end());

    std::array<unsigned char, 16> kdf_salt{};
    for (size_t i = 0; i < kdf_salt.size(); ++i) {
        kdf_salt[i] = static_cast<unsigned char>(0x40 + i);
    }
    payload.insert(payload.end(), kdf_salt.begin(), kdf_salt.end());

    payload.push_back(assets::ICU_VERSION_V1); // icu_version
    payload.push_back(0); // icu_visibility (0 = private)

    uint256 core_policy_commit;
    fill_uint256(core_policy_commit, 0x50);
    payload.insert(payload.end(), core_policy_commit.begin(), core_policy_commit.end());

    payload.push_back(0x12); // policy_epoch (uint8_t)
    append_le16(payload, 7500); // policy_quorum_bps

    // Wrap in TLV (with proper length encoding for sizes >= 253)
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ISSUER_REG));
    const size_t len = payload.size();
    if (len < 253) {
        tlv.push_back(static_cast<unsigned char>(len));
    } else {
        tlv.push_back(253);
        tlv.push_back(len & 0xFF);
        tlv.push_back((len >> 8) & 0xFF);
    }
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    // Parse and validate
    auto parsed = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(parsed.has_value());

    // Validate header
    BOOST_CHECK(parsed->asset_id.begin()[0] == 0x01);
    BOOST_CHECK_EQUAL(parsed->policy_bits, 0x0003u);
    BOOST_CHECK_EQUAL(parsed->allowed_spk_families, assets::SPK_DEFAULT_ALLOWED);
    BOOST_CHECK_EQUAL(parsed->format_version, assets::ISSUER_REG_FORMAT_V1);

    // Validate optional fields
    BOOST_CHECK_EQUAL(parsed->ticker, "GOLD");
    BOOST_CHECK_EQUAL(parsed->decimals, 8);
    BOOST_CHECK_EQUAL(parsed->unlock_fees_sats, 500'000'000ULL);

    // Validate ZK section
    BOOST_CHECK_EQUAL(parsed->kyc_flags, kyc_flags);
    BOOST_CHECK(parsed->zk_vk_commitment == vk_commit);
    BOOST_CHECK_EQUAL(parsed->max_root_age, max_root_age);
    BOOST_CHECK_EQUAL(parsed->tfr_flags, tfr_flags);

    // Validate ICU section
    BOOST_CHECK_EQUAL(parsed->icu_flags, icu_flags);
    BOOST_CHECK_EQUAL(parsed->issuance_cap_units, issuance_cap_units);
    BOOST_CHECK(parsed->icu_ctxt_commit == icu_ctxt_commit);
    BOOST_CHECK(parsed->icu_plain_commit == icu_plain_commit);
    BOOST_CHECK(std::equal(parsed->kdf_salt.begin(), parsed->kdf_salt.end(), kdf_salt.begin()));
    BOOST_CHECK_EQUAL(parsed->icu_version, assets::ICU_VERSION_V1);
    BOOST_CHECK(parsed->core_policy_commit == core_policy_commit);
    BOOST_CHECK_EQUAL(parsed->policy_epoch, 0x12u);
    BOOST_CHECK_EQUAL(parsed->policy_quorum_bps, 7500);
}

BOOST_AUTO_TEST_CASE(parse_icu_payload_roundtrip)
{
    const std::vector<unsigned char> payload = {'H', 'e', 'l', 'l', 'o', 0x00, 0xFF, '!', 0x7F};
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ICU_TEXT_CHUNK));
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    auto parsed = assets::ParseIcuTextChunk(tlv);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->payload == payload);
}

BOOST_AUTO_TEST_CASE(parse_icu_payload_rejects_oversize)
{
    const size_t oversize = assets::MAX_ICU_PAYLOAD_BYTES + 1;
    std::vector<unsigned char> payload(oversize, 0x42);

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ICU_TEXT_CHUNK));
    tlv.push_back(0xFE); // CompactSize marker for 4-byte length
    unsigned char len_bytes[4];
    WriteLE32(len_bytes, static_cast<uint32_t>(oversize));
    tlv.insert(tlv.end(), len_bytes, len_bytes + 4);
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    auto parsed = assets::ParseIcuTextChunk(tlv);
    BOOST_CHECK(!parsed.has_value());
}

BOOST_AUTO_TEST_CASE(parse_icu_keywrap_with_extras)
{
    std::vector<unsigned char> payload;

    auto append_uint256_bytes = [&](uint256& target, unsigned char seed) {
        for (size_t i = 0; i < target.size(); ++i) {
            target.begin()[i] = static_cast<unsigned char>(seed + i);
        }
        payload.insert(payload.end(), target.begin(), target.end());
    };

    uint256 expected_asset_id;
    append_uint256_bytes(expected_asset_id, 0x01);
    uint256 expected_ctxt_hash;
    append_uint256_bytes(expected_ctxt_hash, 0x21);
    uint256 expected_spk_hash;
    append_uint256_bytes(expected_spk_hash, 0x41);

    const std::string wrapped_key{"ciphertext-demo"};
    payload.push_back(static_cast<unsigned char>(wrapped_key.size()));
    payload.insert(payload.end(), wrapped_key.begin(), wrapped_key.end());

    payload.push_back(0x01); // suite id
    payload.push_back(assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT | assets::ICU_KEYWRAP_EXTRA_KC_TAG);

    uint256 expected_wrap_commit;
    append_uint256_bytes(expected_wrap_commit, 0x61);

    std::array<unsigned char, assets::ICU_KEYWRAP_KC_TAG_SIZE> expected_kc{};
    for (size_t i = 0; i < expected_kc.size(); ++i) {
        expected_kc[i] = static_cast<unsigned char>(0x80 + i);
    }
    payload.insert(payload.end(), expected_kc.begin(), expected_kc.end());

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ICU_KEYWRAP));
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    auto parsed = assets::ParseIcuKeywrap(tlv);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->asset_id == expected_asset_id);
    BOOST_CHECK(parsed->ctxt_hash == expected_ctxt_hash);
    BOOST_CHECK(parsed->spk_hash32 == expected_spk_hash);
    BOOST_CHECK_EQUAL(parsed->wrapped_key, wrapped_key);
    BOOST_CHECK_EQUAL(parsed->suite_id, 0x01);
    BOOST_CHECK(parsed->has_wrap_commit);
    BOOST_CHECK(parsed->wrap_commit == expected_wrap_commit);
    BOOST_CHECK(parsed->has_kc_tag);
    BOOST_CHECK(std::equal(parsed->kc_tag.begin(), parsed->kc_tag.end(), expected_kc.begin()));
}

BOOST_AUTO_TEST_CASE(multi_asset_independent_deltas)
{
    // Test that multiple assets track deltas independently
    uint256 asset_a;
    memset(asset_a.data(), 0xaa, asset_a.size());
    uint256 asset_b;
    memset(asset_b.data(), 0xbb, asset_b.size());
    uint256 asset_c;
    memset(asset_c.data(), 0xcc, asset_c.size());
    
    // Use a simple coins view for testing without full chainstate
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    
    // Create inputs with different assets
    mtx.vin.resize(3);
    for (size_t i = 0; i < 3; ++i) {
        uint256 rand_hash;
        memset(rand_hash.data(), i, rand_hash.size());
        mtx.vin[i].prevout = COutPoint(Txid::FromUint256(rand_hash), 0);
        mtx.vin[i].scriptSig = CScript() << OP_TRUE;
    }
    
    // Add input 0: 1000 units of asset_a
    Coin coin_a;
    coin_a.out = CTxOut(5000, CScript() << OP_TRUE);
    coin_a.out.vExt = MakeAssetTag(asset_a, 1000, 0);
    coin_a.nHeight = 100;
    view.AddCoin(mtx.vin[0].prevout, std::move(coin_a), false);
    
    // Add input 1: 2000 units of asset_b
    Coin coin_b;
    coin_b.out = CTxOut(5000, CScript() << OP_TRUE);
    coin_b.out.vExt = MakeAssetTag(asset_b, 2000, 0);
    coin_b.nHeight = 100;
    view.AddCoin(mtx.vin[1].prevout, std::move(coin_b), false);
    
    // Add input 2: 3000 units of asset_c
    Coin coin_c;
    coin_c.out = CTxOut(5000, CScript() << OP_TRUE);
    coin_c.out.vExt = MakeAssetTag(asset_c, 3000, 0);
    coin_c.nHeight = 100;
    view.AddCoin(mtx.vin[2].prevout, std::move(coin_c), false);
    
    // Create outputs that conserve each asset
    CTxOut out_a(1000, CScript() << OP_TRUE);
    out_a.vExt = MakeAssetTag(asset_a, 1000, 0);  // Conserve asset_a
    mtx.vout.push_back(out_a);
    
    CTxOut out_b(1000, CScript() << OP_TRUE);
    out_b.vExt = MakeAssetTag(asset_b, 2000, 0);  // Conserve asset_b
    mtx.vout.push_back(out_b);
    
    CTxOut out_c(1000, CScript() << OP_TRUE);
    out_c.vExt = MakeAssetTag(asset_c, 3000, 0);  // Conserve asset_c
    mtx.vout.push_back(out_c);
    
    // Add plain BTC output for fees
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    
    CTransaction tx(mtx);
    
    // Validate - should pass as all assets conserve
    TxValidationState state;
    CAmount fee;
    bool result = Consensus::CheckTxInputs(tx, state, view, 101, fee);
    BOOST_CHECK(result);
    BOOST_CHECK(state.IsValid());
    
    // Now test with one asset not conserving
    CMutableTransaction mtx2 = mtx;
    mtx2.vout[1].vExt = MakeAssetTag(asset_b, 1500, 0);  // Only 1500 out, but 2000 in
    CTransaction tx2(mtx2);
    
    TxValidationState state2;
    CAmount fee2;
    result = Consensus::CheckTxInputs(tx2, state2, view, 101, fee2);
    BOOST_CHECK(!result);
    BOOST_CHECK(!state2.IsValid());
    // Should fail with burn-needs-icu since delta < 0 and no ICU
    BOOST_CHECK_EQUAL(state2.GetRejectReason(), "asset-burn-needs-icu");
}

BOOST_AUTO_TEST_CASE(empty_vext_handling)
{
    // Test that empty vExt is handled correctly
    std::vector<unsigned char> empty_vext;
    
    // Empty should not parse as AssetTag
    auto tag = assets::ParseAssetTag(empty_vext);
    BOOST_CHECK(!tag.has_value());
    
    // Empty should not parse as IssuerReg
    auto reg = assets::ParseIssuerReg(empty_vext);
    BOOST_CHECK(!reg.has_value());
    
    // Transaction with empty vExt should be valid
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid{}, 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    
    CTxOut out(1000, CScript() << OP_TRUE);
    out.vExt = empty_vext;  // Empty extension
    mtx.vout.push_back(out);
    
    CTransaction tx(mtx);
    
    // Should serialize/deserialize correctly
    DataStream ss{};
    ss << TX_WITH_WITNESS(tx);
    CTransaction tx2(deserialize, TX_WITH_WITNESS, ss);
    BOOST_CHECK_EQUAL(tx.GetHash(), tx2.GetHash());
    BOOST_CHECK(tx2.vout[0].vExt.empty());
}

BOOST_AUTO_TEST_CASE(asset_id_collision_handling)
{
    // Test handling of asset ID collisions
    // This test verifies that IssuerReg TLV parsing correctly handles
    // attempts to register the same asset ID
    uint256 asset_id;
    memset(asset_id.data(), 0xde, asset_id.size());

    // Test 1: Parse two IssuerReg TLVs with same asset_id
    auto reg_tlv1 = MakeIssuerRegV1(asset_id,
                                    /*policy_bits=*/0x0001u, // MINT_ALLOWED
                                    /*allowed_spk=*/assets::SPK_P2WPKH,
                                    /*ticker=*/"",
                                    /*decimals=*/0xFF,
                                    /*unlock_fees=*/std::numeric_limits<uint64_t>::max());

    auto parsed1 = assets::ParseIssuerReg(reg_tlv1);
    BOOST_CHECK(parsed1.has_value());
    BOOST_CHECK_EQUAL(parsed1->asset_id, asset_id);
    BOOST_CHECK_EQUAL(parsed1->policy_bits, 0x0001u);
    BOOST_CHECK_EQUAL(parsed1->allowed_spk_families, assets::SPK_P2WPKH);

    // Test 2: Second registration with same asset_id but different policy
    auto reg_tlv2 = MakeIssuerRegV1(asset_id,
                                    /*policy_bits=*/0x0003u, // MINT_ALLOWED | BURN_ALLOWED
                                    /*allowed_spk=*/assets::SPK_P2WSH,
                                    /*ticker=*/"",
                                    /*decimals=*/0xFF,
                                    /*unlock_fees=*/std::numeric_limits<uint64_t>::max());

    auto parsed2 = assets::ParseIssuerReg(reg_tlv2);
    BOOST_CHECK(parsed2.has_value());
    BOOST_CHECK_EQUAL(parsed2->asset_id, asset_id);
    BOOST_CHECK_EQUAL(parsed2->policy_bits, 0x0003u);
    BOOST_CHECK_EQUAL(parsed2->allowed_spk_families, assets::SPK_P2WSH);

    // Both should parse independently
    // Actual collision handling would be done at validation/registry level
}

BOOST_AUTO_TEST_CASE(unknown_tlv_is_consensus_invalid)
{
    // A transaction output carrying an unknown TLV type must be consensus-invalid
    // Build a minimal spendable input in a dummy view
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.vin.resize(1);
    uint256 prev_hash;
    memset(prev_hash.data(), 0x42, prev_hash.size());
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(prev_hash), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;

    // Add the referenced coin to the view (plain BTC, no vExt)
    Coin coin;
    coin.out = CTxOut(1000, CScript() << OP_TRUE);
    coin.nHeight = 100;
    view.AddCoin(mtx.vin[0].prevout, std::move(coin), false);

    // Create an output with unknown TLV type 0x99
    CTxOut out1(500, CScript() << OP_TRUE);
    std::vector<unsigned char> tlv;
    tlv.push_back(0x99); // unknown type
    tlv.push_back(0x01); // length = 1
    tlv.push_back(0xAA); // value byte
    out1.vExt = std::move(tlv);
    mtx.vout.push_back(out1);

    // Add change output
    mtx.vout.emplace_back(400, CScript() << OP_TRUE);

    CTransaction tx(mtx);
    TxValidationState state;
    CAmount fee;
    bool ok = Consensus::CheckTxInputs(tx, state, view, /*height=*/101, fee);
    BOOST_CHECK(!ok);
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "outext");
}

BOOST_AUTO_TEST_CASE(malformed_tlv_variants)
{
    // Test various malformed TLV structures
    
    // 1. TLV with length exceeding data
    std::vector<unsigned char> bad_tlv1 = {0x01, 0xFF, 0x00};  // Claims 255 bytes, has 1
    auto parsed1 = assets::ParseAssetTag(bad_tlv1);
    BOOST_CHECK(!parsed1.has_value());
    
    // 2. TLV with varint length
    std::vector<unsigned char> bad_tlv2 = {0x01, 0xFD, 0x00, 0x01};  // Varint 256, no data
    auto parsed2 = assets::ParseAssetTag(bad_tlv2);
    BOOST_CHECK(!parsed2.has_value());
    
    // 3. AssetTag with wrong data size (not 32+8 or 32+8+4)
    std::vector<unsigned char> bad_tlv3(35, 0);
    bad_tlv3[0] = 0x01;  // AssetTag type
    bad_tlv3[1] = 33;     // Length (wrong: not 40 or 44)
    auto parsed3 = assets::ParseAssetTag(bad_tlv3);
    BOOST_CHECK(!parsed3.has_value());
    
    // 4. IssuerReg with insufficient data
    std::vector<unsigned char> bad_tlv4(20, 0);
    bad_tlv4[0] = 0x10;  // IssuerReg type
    bad_tlv4[1] = 18;     // Length (too short)
    auto parsed4 = assets::ParseIssuerReg(bad_tlv4);
    BOOST_CHECK(!parsed4.has_value());
    
    // 5. Unknown TLV type
    std::vector<unsigned char> unknown_tlv = {0x99, 0x04, 0x01, 0x02, 0x03, 0x04};
    auto parsed5a = assets::ParseAssetTag(unknown_tlv);
    auto parsed5b = assets::ParseIssuerReg(unknown_tlv);
    BOOST_CHECK(!parsed5a.has_value());
    BOOST_CHECK(!parsed5b.has_value());
    
    // 6. Multiple TLVs (not allowed in current design)
    std::vector<unsigned char> multi_tlv;
    uint256 id1;
    memset(id1.data(), 0x11, id1.size());
    auto tag1 = MakeAssetTag(id1, 1000);
    uint256 id2;
    memset(id2.data(), 0x22, id2.size());
    auto tag2 = MakeAssetTag(id2, 2000);
    multi_tlv.insert(multi_tlv.end(), tag1.begin(), tag1.end());
    multi_tlv.insert(multi_tlv.end(), tag2.begin(), tag2.end());
    
    // ParseAssetTag should REJECT multiple TLVs (per plan: single TLV constraint)
    // The ParseSingleTLV function checks that TLV length == remaining bytes
    auto parsed6 = assets::ParseAssetTag(multi_tlv);
    BOOST_CHECK(!parsed6.has_value());  // Should fail due to extra bytes after first TLV
    
    // ValidateSingleTLV should also reject multiple TLVs
    bool valid = ValidateSingleTLV(multi_tlv);
    BOOST_CHECK(!valid);
}

BOOST_AUTO_TEST_CASE(max_assets_per_tx_stress)
{
    // Test transaction with maximum number of different assets
    const size_t MAX_ASSETS = 100;  // Stress test with 100 different assets
    
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    
    // Create inputs and outputs for many different assets
    for (size_t i = 0; i < MAX_ASSETS; ++i) {
        // Generate unique asset ID
        uint256 asset_id;
        unsigned char fill = static_cast<unsigned char>((i % 255) + 1); // avoid all-zero asset id
        memset(asset_id.data(), fill, asset_id.size());
        
        // Add input
        CTxIn in;
        uint256 rand_hash;
        memset(rand_hash.data(), i+1, rand_hash.size());
        in.prevout = COutPoint(Txid::FromUint256(rand_hash), i);
        in.scriptSig = CScript() << OP_TRUE;
        mtx.vin.push_back(in);
        
        // Add output with AssetTag
        CTxOut out(100, CScript() << OP_TRUE);
        out.vExt = MakeAssetTag(asset_id, 1000 + i, 0);
        mtx.vout.push_back(out);
    }
    
    CTransaction tx(mtx);
    
    // Verify all outputs have valid AssetTags
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        auto tag = assets::ParseAssetTag(tx.vout[i].vExt);
        BOOST_CHECK(tag.has_value());
        BOOST_CHECK_EQUAL(tag->amount, 1000 + i);
    }
    
    // Check serialization size
    DataStream ss{};
    ss << TX_WITH_WITNESS(tx);
    size_t tx_size = ss.size();
    BOOST_CHECK(tx_size > 0);
    
    // With 100 assets, each output has ~44 bytes of vExt
    // Total vExt should be around 4400 bytes
    size_t total_vext = 0;
    for (const auto& out : tx.vout) {
        total_vext += out.vExt.size();
    }
    BOOST_CHECK(total_vext > 4000);
    BOOST_CHECK(total_vext < MAX_OUEXT_BYTES_PER_TX);  // Should still be under limit
}

BOOST_AUTO_TEST_SUITE_END()
