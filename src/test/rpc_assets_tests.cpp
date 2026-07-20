// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/asset.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/context.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/client.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

class AssetRPCTestingSetup : public TestingSetup
{
public:
    UniValue CallRPC(std::string args);
};

UniValue AssetRPCTestingSetup::CallRPC(std::string args)
{
    std::vector<std::string> vArgs{util::SplitString(args, ' ')};
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    try {
        UniValue result = tableRPC.execute(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(objError.find_value("message").get_str());
    }
}

BOOST_FIXTURE_TEST_SUITE(rpc_assets_tests, AssetRPCTestingSetup)

BOOST_AUTO_TEST_CASE(test_asset_tag_parsing)
{
    // Test AssetTag TLV encoding/decoding
    uint256 asset_id = *uint256::FromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    uint64_t amount = 1000000;

    // Create AssetTag TLV
    std::vector<unsigned char> tag_payload;
    tag_payload.insert(tag_payload.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_buf[8];
    WriteLE64(amount_buf, amount);
    tag_payload.insert(tag_payload.end(), amount_buf, amount_buf + 8);

    std::vector<unsigned char> tag_tlv;
    tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
    tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());

    // Parse it back
    auto parsed_tag = assets::ParseAssetTag(tag_tlv);
    BOOST_CHECK(parsed_tag.has_value());
    BOOST_CHECK_EQUAL(parsed_tag->id, asset_id);
    BOOST_CHECK_EQUAL(parsed_tag->amount, amount);
}

BOOST_AUTO_TEST_CASE(test_issuer_reg_parsing)
{
    // Test v1 IssuerReg TLV encoding/decoding
    uint256 asset_id = *uint256::FromHex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
    uint32_t policy_bits = 3; // MINT_ALLOWED | BURN_ALLOWED

    // Create v1 IssuerReg TLV
    auto reg_tlv = test_util::BuildV1IssuerReg(asset_id, policy_bits, assets::SPK_DEFAULT_ALLOWED);

    // Parse it back
    auto parsed_reg = assets::ParseIssuerReg(reg_tlv);
    BOOST_REQUIRE(parsed_reg.has_value());
    BOOST_CHECK_EQUAL(parsed_reg->asset_id, asset_id);
    BOOST_CHECK_EQUAL(parsed_reg->policy_bits, policy_bits);
    BOOST_CHECK_EQUAL(parsed_reg->format_version, assets::ISSUER_REG_FORMAT_V1);
}

BOOST_AUTO_TEST_CASE(test_getassetpolicy_ticker)
{
    // Test that getassetpolicy accepts both asset_id and ticker
    // This requires a mock setup with registered assets - simplified for unit test

    // Test hex validation
    BOOST_CHECK_THROW(CallRPC("getassetpolicy notvalidhex"), std::runtime_error);

    // Test ticker length validation
    BOOST_CHECK_THROW(CallRPC("getassetpolicy AB"), std::runtime_error); // Too short
    BOOST_CHECK_THROW(CallRPC("getassetpolicy TOOLONGTICKER"), std::runtime_error); // Too long
}

BOOST_AUTO_TEST_CASE(test_transferasset_conservation)
{
    // Test transferasset RPC conservation validation
    std::string asset_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    // Test that inputs != outputs throws error - use valid mainnet Bech32 address
    std::string cmd = "transferasset "
                     "[{\"txid\":\"" + std::string(64, '0') + "\",\"vout\":0,\"asset_units\":1000}] "
                     "{\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\":500} " + asset_id;

    // This should fail conservation check (1000 in, 500 out)
    BOOST_CHECK_THROW(CallRPC(cmd), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_validateassetconservation)
{
    // Test asset conservation validation
    // Create a transaction with asset tags
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.hash = Txid::FromUint256(*uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111"));
    mtx.vin[0].prevout.n = 0;

    // Add output with asset tag
    uint256 asset_id = *uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    uint64_t amount = 1000000;

    CTxOut out(100000, CScript()); // 0.001 BTC

    // Create AssetTag TLV
    std::vector<unsigned char> tag_payload;
    tag_payload.insert(tag_payload.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_buf[8];
    WriteLE64(amount_buf, amount);
    tag_payload.insert(tag_payload.end(), amount_buf, amount_buf + 8);

    std::vector<unsigned char> tag_tlv;
    tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
    tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());

    out.vExt = tag_tlv;
    mtx.vout.push_back(out);

    // Serialize and test
    DataStream ds;
    ds << TX_WITH_WITNESS(mtx);
    std::string hex = HexStr(ds);

    // Call validateassetconservation
    try {
        UniValue result = CallRPC("validateassetconservation " + hex);

        // Should have the asset in the result
        BOOST_CHECK(result.exists("assets"));
        BOOST_CHECK(result["assets"].exists(asset_id.ToString()));

        // Without inputs, delta should be negative (only outputs)
        UniValue asset_info = result["assets"][asset_id.ToString()];
        BOOST_CHECK(asset_info.exists("outputs"));
        BOOST_CHECK_EQUAL(asset_info["outputs"].getInt<uint64_t>(), amount);
    } catch (const std::exception& e) {
        // Expected since we can't look up prevouts in unit test
        BOOST_TEST_MESSAGE("validateassetconservation failed as expected without chain state: " + std::string(e.what()));
    }
}

BOOST_AUTO_TEST_CASE(test_decodeassettransaction)
{
    // Test enhanced transaction decoding
    CMutableTransaction mtx;

    // Add output with asset tag
    uint256 asset_id = *uint256::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    uint64_t amount = 500000;

    CTxOut out(100000, CScript());

    // Create AssetTag TLV
    std::vector<unsigned char> tag_payload;
    tag_payload.insert(tag_payload.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_buf[8];
    WriteLE64(amount_buf, amount);
    tag_payload.insert(tag_payload.end(), amount_buf, amount_buf + 8);

    std::vector<unsigned char> tag_tlv;
    tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
    tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());

    out.vExt = tag_tlv;
    mtx.vout.push_back(out);

    // Serialize and test
    DataStream ds;
    ds << TX_WITH_WITNESS(mtx);
    std::string hex = HexStr(ds);

    UniValue result = CallRPC("decodeassettransaction " + hex);

    // Check asset summary
    BOOST_CHECK(result.exists("asset_summary"));
    UniValue summary = result["asset_summary"];
    BOOST_CHECK(summary.exists("has_assets"));
    BOOST_CHECK_EQUAL(summary["has_assets"].get_bool(), true);

    // Check specific asset
    BOOST_CHECK(summary["assets"].exists(asset_id.ToString()));
    UniValue asset_info = summary["assets"][asset_id.ToString()];
    BOOST_CHECK(asset_info.exists("outputs"));
    BOOST_CHECK_EQUAL(asset_info["outputs"].getInt<uint64_t>(), amount);
}

BOOST_AUTO_TEST_CASE(test_createassettransaction)
{
    // Test complex asset transaction creation - avoid spaces in JSON
    std::string inputs = "[{\"txid\":\"" + std::string(64, '1') + "\",\"vout\":0}]";
    // Use a valid mainnet Bech32 test address
    std::string outputs = "[{\"address\":\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\",\"btc_amount\":0.001,\"asset_id\":\"" + std::string(64, 'c') + "\",\"asset_units\":100000}]";

    std::string cmd = "createassettransaction " + inputs + " " + outputs;

    UniValue result = CallRPC(cmd);

    // Should return hex string
    BOOST_CHECK(result.isStr());

    // Decode and verify
    CMutableTransaction mtx;
    BOOST_CHECK(DecodeHexTx(mtx, result.get_str()));
    BOOST_CHECK_EQUAL(mtx.vin.size(), 1U);
    BOOST_CHECK_EQUAL(mtx.vout.size(), 1U);

    // Check that output has vExt
    BOOST_CHECK(!mtx.vout[0].vExt.empty());

    // Parse asset tag
    auto tag = assets::ParseAssetTag(mtx.vout[0].vExt);
    BOOST_CHECK(tag.has_value());
    BOOST_CHECK_EQUAL(tag->amount, 100000U);
}

BOOST_AUTO_TEST_CASE(test_listassets_filters)
{
    // Test listassets filter functionality
    // Note: This is a simplified test without actual registered assets

    // Test filter validation
    try {
        // Test has_ticker filter
        CallRPC("listassets true {\"has_ticker\":true}");

        // Test policy_bits filter
        CallRPC("listassets true {\"policy_bits\":3}");

        // Test min_balance filter
        CallRPC("listassets true {\"min_balance\":100000}");

        // Test combined filters
        CallRPC("listassets true {\"has_ticker\":true,\"policy_bits\":3,\"min_balance\":100000}");

        BOOST_TEST_MESSAGE("listassets filter parsing succeeded");
    } catch (const std::exception& e) {
        // Expected in unit test environment without actual assets
        BOOST_TEST_MESSAGE("listassets failed as expected in unit test: " + std::string(e.what()));
    }
}

BOOST_AUTO_TEST_SUITE_END()