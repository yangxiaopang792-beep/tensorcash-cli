// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <assets/asset.h>
#include <assets/registry.h>
#include <consensus/amount.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(asset_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(test_asset_metadata_storage)
{
    // Test AssetMetadata storage and retrieval
    auto& wallet = m_wallet;
    LOCK(wallet.cs_wallet);

    // Create test metadata
    AssetMetadata metadata;
    metadata.has_ticker = true;
    metadata.ticker = "GOLD";
    metadata.has_decimals = true;
    metadata.decimals = 8;

    // Store metadata for a test outpoint
    COutPoint test_outpoint(Txid::FromUint256(uint256::ZERO), 0);
    wallet.SetAssetMetadata(test_outpoint, metadata);

    // Retrieve and verify
    auto retrieved = wallet.GetAssetMetadata(test_outpoint);
    BOOST_CHECK(retrieved.has_value());
    BOOST_CHECK_EQUAL(retrieved->ticker, "GOLD");
    BOOST_CHECK_EQUAL(retrieved->decimals, 8);
}

BOOST_AUTO_TEST_CASE(test_asset_ticker_validation)
{
    // Test ticker validation rules
    std::vector<std::pair<std::string, bool>> test_cases = {
        {"GOLD", true},      // Valid 4-char
        {"USD", true},       // Valid 3-char
        {"TENSORCASH", true},// Valid 11-char (max)
        {"AB", false},       // Too short (< 3)
        {"TOOLONGTICKER", false}, // Too long (> 11)
        {"1BTC", false},     // Starts with number
        {"BT-C", false},     // Contains invalid char
        {"btc", true},       // Lowercase (should be converted to uppercase)
        {"", false},         // Empty
    };

    for (const auto& [ticker, should_be_valid] : test_cases) {
        std::string test_ticker = ticker;

        // Convert to uppercase (as the implementation does)
        std::transform(test_ticker.begin(), test_ticker.end(), test_ticker.begin(),
            [](unsigned char c) { return std::toupper(c); });

        if (should_be_valid) {
            // Valid ticker checks
            bool valid = test_ticker.size() >= 3 && test_ticker.size() <= 11;
            if (valid && !test_ticker.empty()) {
                valid = std::isalpha(test_ticker[0]);
                for (char c : test_ticker) {
                    if (!std::isalnum(c)) {
                        valid = false;
                        break;
                    }
                }
            }
            BOOST_CHECK_MESSAGE(valid == should_be_valid,
                "Ticker " + ticker + " validation failed");
        }
    }
}

BOOST_AUTO_TEST_CASE(test_asset_decimals_validation)
{
    // Test decimals validation (0-18 range)
    std::vector<std::pair<uint8_t, bool>> test_cases = {
        {0, true},   // Min valid
        {8, true},   // Common value (Bitcoin-like)
        {18, true},  // Max valid
        {19, false}, // Too large
        {255, false},// Way too large
    };

    for (const auto& [decimals, should_be_valid] : test_cases) {
        bool valid = decimals <= 18;
        BOOST_CHECK_EQUAL(valid, should_be_valid);
    }
}

BOOST_AUTO_TEST_CASE(test_asset_id_validation)
{
    // Test asset ID validation (32-byte hex)
    std::vector<std::pair<std::string, bool>> test_cases = {
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true}, // Valid 64-char hex
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true}, // Valid mixed hex
        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true}, // Valid uppercase
        {"aaa", false},  // Too short
        {"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", false}, // Invalid hex chars
        {"", false},     // Empty
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00", false}, // Too long
    };

    for (const auto& [asset_id_str, should_be_valid] : test_cases) {
        auto asset_id = uint256::FromHex(asset_id_str);
        BOOST_CHECK_EQUAL(asset_id.has_value(), should_be_valid);
    }
}

BOOST_AUTO_TEST_CASE(test_issuer_reg_tlv_construction)
{
    // Test IssuerReg TLV construction
    uint256 asset_id;
    asset_id = *uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    uint32_t policy_bits = 3; // MINT_ALLOWED | BURN_ALLOWED
    uint16_t allowed_families = 28; // P2WPKH | P2WSH | P2TR
    uint64_t unlock_fees = 510000000; // 5.1 BTC in sats

    // Build IssuerReg TLV payload
    std::vector<unsigned char> payload;
    payload.reserve(32 + 4 + 2 + 8);

    // Asset ID (32 bytes)
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());

    // Policy bits (4 bytes, little-endian)
    unsigned char pb[4];
    WriteLE32(pb, policy_bits);
    payload.insert(payload.end(), pb, pb + 4);

    // Allowed families (2 bytes, little-endian)
    unsigned char ab[2];
    ab[0] = allowed_families & 0xFF;
    ab[1] = (allowed_families >> 8) & 0xFF;
    payload.insert(payload.end(), ab, ab + 2);

    // Unlock fees (8 bytes, little-endian)
    unsigned char ub[8];
    WriteLE64(ub, unlock_fees);
    payload.insert(payload.end(), ub, ub + 8);

    // Create TLV
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
    tlv.push_back(static_cast<uint8_t>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    // Verify TLV structure
    BOOST_CHECK_EQUAL(tlv[0], 0x10); // ISSUER_REG type
    BOOST_CHECK_EQUAL(tlv[1], 46);   // Expected payload size
    BOOST_CHECK_EQUAL(tlv.size(), 48); // Type + length + payload
}

BOOST_AUTO_TEST_CASE(test_asset_tag_tlv_construction)
{
    // Test AssetTag TLV construction
    uint256 asset_id;
    asset_id = *uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    uint64_t units = 100000000; // 1.0 with 8 decimals

    // Build AssetTag TLV payload
    std::vector<unsigned char> payload;
    payload.reserve(32 + 8);

    // Asset ID (32 bytes)
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());

    // Units (8 bytes, little-endian)
    unsigned char au[8];
    WriteLE64(au, units);
    payload.insert(payload.end(), au, au + 8);

    // Create TLV
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(static_cast<uint8_t>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    // Verify TLV structure
    BOOST_CHECK_EQUAL(tlv[0], 0x01); // ASSET_TAG type
    BOOST_CHECK_EQUAL(tlv[1], 40);   // Expected payload size
    BOOST_CHECK_EQUAL(tlv.size(), 42); // Type + length + payload
}

BOOST_AUTO_TEST_CASE(test_ticker_tlv_extension)
{
    // Test IssuerReg TLV with ticker extension
    uint256 asset_id;
    asset_id = *uint256::FromHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    uint32_t policy_bits = 3;
    uint16_t allowed_families = 28;
    uint64_t unlock_fees = 510000000;
    std::string ticker = "GOLD";
    uint8_t decimals = 8;

    // Build IssuerReg TLV payload with ticker
    std::vector<unsigned char> payload;
    payload.reserve(32 + 4 + 2 + 8 + 1 + ticker.size() + 1);

    // Standard fields
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char pb[4]; WriteLE32(pb, policy_bits);
    payload.insert(payload.end(), pb, pb + 4);
    unsigned char ab[2]; ab[0] = allowed_families & 0xFF; ab[1] = (allowed_families >> 8) & 0xFF;
    payload.insert(payload.end(), ab, ab + 2);
    unsigned char ub[8]; WriteLE64(ub, unlock_fees);
    payload.insert(payload.end(), ub, ub + 8);

    // Ticker extension
    payload.push_back(static_cast<unsigned char>(ticker.size()));
    payload.insert(payload.end(), ticker.begin(), ticker.end());
    payload.push_back(decimals);

    // Create TLV
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
    tlv.push_back(static_cast<uint8_t>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    // Verify TLV structure
    BOOST_CHECK_EQUAL(tlv[0], 0x10); // ISSUER_REG type
    BOOST_CHECK_EQUAL(tlv[1], 52);   // 46 base + 1 (ticker len) + 4 (ticker) + 1 (decimals)
    BOOST_CHECK_EQUAL(tlv.size(), 54);
}

BOOST_AUTO_TEST_CASE(test_format_asset_units)
{
    // Test decimal formatting of asset units
    struct TestCase {
        uint64_t units;
        uint8_t decimals;
        std::string expected;
    };

    std::vector<TestCase> test_cases = {
        {100000000, 8, "1.00000000"},      // 1 BTC equivalent
        {50000000, 8, "0.50000000"},       // 0.5 BTC
        {1, 8, "0.00000001"},               // 1 satoshi
        {100000000, 0, "100000000"},       // No decimals
        {1234567890, 6, "1234.567890"},    // 6 decimals
        {1000, 3, "1.000"},                 // 3 decimals
        {0, 8, "0.00000000"},               // Zero
        {12345678901234567, 18, "0.012345678901234567"}, // Max decimals
    };

    for (const auto& tc : test_cases) {
        std::string result;
        if (tc.decimals == 0) {
            result = std::to_string(tc.units);
        } else {
            uint64_t factor = 1;
            for (uint8_t i = 0; i < tc.decimals; ++i) {
                factor *= 10;
            }
            uint64_t whole = tc.units / factor;
            uint64_t remainder = tc.units % factor;

            // Format with leading zeros for decimal part
            std::string decimal_part = std::to_string(remainder);
            while (decimal_part.size() < tc.decimals) {
                decimal_part = "0" + decimal_part;
            }
            result = std::to_string(whole) + "." + decimal_part;
        }
        BOOST_CHECK_EQUAL(result, tc.expected);
    }
}

BOOST_AUTO_TEST_CASE(test_coin_control_asset_settings)
{
    // Test CCoinControl settings for asset operations
    CCoinControl cc;

    // Test asset-specific coin control settings
    uint256 test_asset_id;
    test_asset_id = *uint256::FromHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    cc.m_required_asset_id = test_asset_id;
    cc.m_allow_icu_selection = true;
    cc.m_allow_other_inputs = true;

    BOOST_CHECK(cc.m_required_asset_id.has_value());
    BOOST_CHECK_EQUAL(cc.m_required_asset_id->ToString(), test_asset_id.ToString());
    BOOST_CHECK(cc.m_allow_icu_selection);
    BOOST_CHECK(cc.m_allow_other_inputs);

    // Test fee rate settings
    cc.fOverrideFeeRate = true;
    cc.m_feerate = CFeeRate(10000); // 10 sat/vB
    BOOST_CHECK(cc.fOverrideFeeRate);
    BOOST_CHECK(cc.m_feerate.has_value());
    BOOST_CHECK_EQUAL(cc.m_feerate->GetFeePerK(), 10000);

    // Test RBF settings
    cc.m_signal_bip125_rbf = true;
    BOOST_CHECK(cc.m_signal_bip125_rbf.value());
}

BOOST_AUTO_TEST_CASE(test_policy_bits)
{
    // Test policy bit flags
    const uint32_t MINT_ALLOWED = 0x0001;
    const uint32_t BURN_ALLOWED = 0x0002;
    const uint32_t FUTURE_FLAG = 0x0004;

    // Test combinations
    uint32_t mint_only = MINT_ALLOWED;
    uint32_t burn_only = BURN_ALLOWED;
    uint32_t mint_and_burn = MINT_ALLOWED | BURN_ALLOWED;
    uint32_t all_flags = MINT_ALLOWED | BURN_ALLOWED | FUTURE_FLAG;

    BOOST_CHECK_EQUAL(mint_only, 1);
    BOOST_CHECK_EQUAL(burn_only, 2);
    BOOST_CHECK_EQUAL(mint_and_burn, 3);
    BOOST_CHECK_EQUAL(all_flags, 7);

    // Test flag checking
    BOOST_CHECK(mint_and_burn & MINT_ALLOWED);
    BOOST_CHECK(mint_and_burn & BURN_ALLOWED);
    BOOST_CHECK(!(mint_only & BURN_ALLOWED));
    BOOST_CHECK(!(burn_only & MINT_ALLOWED));
}

BOOST_AUTO_TEST_CASE(test_allowed_spk_families)
{
    // Test allowed script pubkey families
    const uint16_t SPK_P2PK = 0x0001;
    const uint16_t SPK_P2PKH = 0x0002;
    const uint16_t SPK_P2WPKH = 0x0004;
    const uint16_t SPK_P2WSH = 0x0008;
    const uint16_t SPK_P2TR = 0x0010;

    // Common combinations
    uint16_t legacy_only = SPK_P2PK | SPK_P2PKH;
    uint16_t segwit_v0 = SPK_P2WPKH | SPK_P2WSH;
    uint16_t modern = SPK_P2WPKH | SPK_P2WSH | SPK_P2TR;
    uint16_t all_families = SPK_P2PK | SPK_P2PKH | SPK_P2WPKH | SPK_P2WSH | SPK_P2TR;

    BOOST_CHECK_EQUAL(legacy_only, 3);
    BOOST_CHECK_EQUAL(segwit_v0, 12);
    BOOST_CHECK_EQUAL(modern, 28); // Default in our implementation
    BOOST_CHECK_EQUAL(all_families, 31);

    // Test family checking
    BOOST_CHECK(modern & SPK_P2WPKH);
    BOOST_CHECK(modern & SPK_P2WSH);
    BOOST_CHECK(modern & SPK_P2TR);
    BOOST_CHECK(!(modern & SPK_P2PK));
    BOOST_CHECK(!(modern & SPK_P2PKH));
}

BOOST_AUTO_TEST_CASE(test_bond_validation)
{
    // Test ICU bond amount validation
    const CAmount MIN_BOND = 5 * COIN; // 5 BTC minimum

    std::vector<std::pair<CAmount, bool>> test_cases = {
        {5 * COIN, true},       // Exact minimum
        {5.1 * COIN, true},     // Above minimum (common in tests)
        {10 * COIN, true},      // Well above minimum
        {4.9 * COIN, false},    // Below minimum
        {1 * COIN, false},      // Way below minimum
        {0, false},             // Zero
    };

    for (const auto& [amount, should_be_valid] : test_cases) {
        bool valid = amount >= MIN_BOND;
        BOOST_CHECK_EQUAL(valid, should_be_valid);
    }
}

BOOST_AUTO_TEST_CASE(test_transaction_structure_registration)
{
    // Test transaction structure for asset registration
    CMutableTransaction mtx;

    // ICU output (bond)
    CAmount bond_amount = 5.1 * COIN;
    CScript icu_script = GetScriptForDestination(WitnessV1Taproot()); // P2TR
    mtx.vout.emplace_back(bond_amount, icu_script);

    // Attach IssuerReg TLV
    uint256 asset_id;
    asset_id = *uint256::FromHex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

    std::vector<unsigned char> payload;
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char pb[4]; WriteLE32(pb, 3);
    payload.insert(payload.end(), pb, pb + 4);
    unsigned char ab[2] = {28, 0};
    payload.insert(payload.end(), ab, ab + 2);
    unsigned char ub[8]; WriteLE64(ub, 510000000);
    payload.insert(payload.end(), ub, ub + 8);

    std::vector<unsigned char> tlv;
    tlv.push_back(0x10); // ISSUER_REG
    tlv.push_back(static_cast<uint8_t>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    mtx.vout[0].vExt = std::move(tlv);

    // Verify structure
    BOOST_CHECK_EQUAL(mtx.vout.size(), 1);
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, bond_amount);
    BOOST_CHECK(!mtx.vout[0].vExt.empty());
    BOOST_CHECK_EQUAL(mtx.vout[0].vExt[0], 0x10);
}

BOOST_AUTO_TEST_CASE(test_transaction_structure_minting)
{
    // Test transaction structure for asset minting
    CMutableTransaction mtx;

    // Input: ICU from previous registration
    Txid icu_txid{Txid::FromUint256(uint256::ONE)};
    mtx.vin.emplace_back(COutPoint(icu_txid, 0));

    // Output 0: ICU rotation (maintain bond)
    CAmount bond_amount = 5.1 * COIN;
    CScript icu_script = GetScriptForDestination(WitnessV1Taproot());
    mtx.vout.emplace_back(bond_amount, icu_script);

    // Attach IssuerReg TLV for rotation
    uint256 asset_id;
    asset_id = *uint256::FromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    std::vector<unsigned char> reg_payload;
    reg_payload.insert(reg_payload.end(), asset_id.begin(), asset_id.end());
    unsigned char pb[4]; WriteLE32(pb, 3);
    reg_payload.insert(reg_payload.end(), pb, pb + 4);
    unsigned char ab[2] = {28, 0};
    reg_payload.insert(reg_payload.end(), ab, ab + 2);
    unsigned char ub[8]; WriteLE64(ub, 510000000);
    reg_payload.insert(reg_payload.end(), ub, ub + 8);

    std::vector<unsigned char> reg_tlv;
    reg_tlv.push_back(0x10); // ISSUER_REG
    reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
    reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());
    mtx.vout[0].vExt = std::move(reg_tlv);

    // Output 1: Minted assets
    CAmount asset_btc = 0.001 * COIN;
    CScript asset_script = GetScriptForDestination(WitnessV1Taproot());
    mtx.vout.emplace_back(asset_btc, asset_script);

    // Attach AssetTag TLV
    uint64_t units = 1000000; // 1.0 with 6 decimals
    std::vector<unsigned char> tag_payload;
    tag_payload.insert(tag_payload.end(), asset_id.begin(), asset_id.end());
    unsigned char au[8]; WriteLE64(au, units);
    tag_payload.insert(tag_payload.end(), au, au + 8);

    std::vector<unsigned char> tag_tlv;
    tag_tlv.push_back(0x01); // ASSET_TAG
    tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
    tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());
    mtx.vout[1].vExt = std::move(tag_tlv);

    // Verify structure
    BOOST_CHECK_EQUAL(mtx.vin.size(), 1);
    BOOST_CHECK_EQUAL(mtx.vout.size(), 2);
    BOOST_CHECK_EQUAL(mtx.vout[0].vExt[0], 0x10); // ICU rotation
    BOOST_CHECK_EQUAL(mtx.vout[1].vExt[0], 0x01); // Asset mint
}

BOOST_AUTO_TEST_CASE(test_transaction_structure_burning)
{
    // Test transaction structure for asset burning
    CMutableTransaction mtx;

    // Input 0: ICU for authorization
    Txid icu_txid{Txid::FromUint256(uint256::ONE)};
    mtx.vin.emplace_back(COutPoint(icu_txid, 0));

    // Input 1: Asset to burn
    Txid asset_txid{Txid::FromUint256(uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000002").value())};
    mtx.vin.emplace_back(COutPoint(asset_txid, 1));

    // Output: ICU rotation only (no asset output = burn)
    CAmount bond_amount = 5.1 * COIN;
    CScript icu_script = GetScriptForDestination(WitnessV1Taproot());
    mtx.vout.emplace_back(bond_amount, icu_script);

    // Attach IssuerReg TLV for rotation
    uint256 asset_id;
    asset_id = *uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111");

    std::vector<unsigned char> reg_payload;
    reg_payload.insert(reg_payload.end(), asset_id.begin(), asset_id.end());
    unsigned char pb[4]; WriteLE32(pb, 3);
    reg_payload.insert(reg_payload.end(), pb, pb + 4);
    unsigned char ab[2] = {28, 0};
    reg_payload.insert(reg_payload.end(), ab, ab + 2);
    unsigned char ub[8]; WriteLE64(ub, 510000000);
    reg_payload.insert(reg_payload.end(), ub, ub + 8);

    std::vector<unsigned char> reg_tlv;
    reg_tlv.push_back(0x10); // ISSUER_REG
    reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
    reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());
    mtx.vout[0].vExt = std::move(reg_tlv);

    // Verify structure
    BOOST_CHECK_EQUAL(mtx.vin.size(), 2); // ICU + asset input
    BOOST_CHECK_EQUAL(mtx.vout.size(), 1); // Only ICU output
    BOOST_CHECK_EQUAL(mtx.vout[0].vExt[0], 0x10); // ICU rotation
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet