// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <key.h>
#include <key_io.h>
#include <script/script.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <base58.h>

#include <algorithm>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);
    CKey privkey;
    CTxDestination destination;
    SelectParams(ChainType::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        const std::vector<std::byte> exp_payload{ParseHex<std::byte>(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        bool try_case_flip = metadata.find_value("tryCaseFlip").isNull() ? false : metadata.find_value("tryCaseFlip").get_bool();
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            // Must be valid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(privkey.IsValid(), "!IsValid:" + strTest);
            BOOST_CHECK_MESSAGE(privkey.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(std::ranges::equal(privkey, exp_payload), "key mismatch:" + strTest);

            // Private key must be invalid public key
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid privkey as pubkey:" + strTest);
        } else {
            // Must be valid public key
            destination = DecodeDestination(exp_base58string);
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            BOOST_CHECK_MESSAGE(EncodeSecret(key) == exp_base58string, "result mismatch: " + strTest);
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            std::string address = EncodeDestination(dest);

            BOOST_CHECK_EQUAL(address, exp_base58string);
        }
    }

    SelectParams(ChainType::MAIN);
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

// Test that addresses from one network don't decode on another (cross-network rejection)
BOOST_AUTO_TEST_CASE(cross_network_rejection)
{
    // Generate a key for testing
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    
    // Test Bitcoin -> Tensor rejection
    {
        SelectParams(ChainType::MAIN);
        CTxDestination btc_p2pkh = PKHash(pubkey);
        std::string btc_address = EncodeDestination(btc_p2pkh);
        
        // Should decode on Bitcoin mainnet
        BOOST_CHECK(IsValidDestinationString(btc_address));
        
        // Should NOT decode on Tensor networks
        SelectParams(ChainType::TENSOR_MAIN);
        BOOST_CHECK(!IsValidDestinationString(btc_address));
        
        SelectParams(ChainType::TENSOR_TEST);
        BOOST_CHECK(!IsValidDestinationString(btc_address));
        
        SelectParams(ChainType::TENSOR_REG);
        BOOST_CHECK(!IsValidDestinationString(btc_address));
    }
    
    // Test Tensor -> Bitcoin rejection
    {
        SelectParams(ChainType::TENSOR_MAIN);
        CTxDestination tensor_p2pkh = PKHash(pubkey);
        std::string tensor_address = EncodeDestination(tensor_p2pkh);
        
        // Should decode on Tensor mainnet
        BOOST_CHECK(IsValidDestinationString(tensor_address));
        
        // Should NOT decode on Bitcoin networks
        SelectParams(ChainType::MAIN);
        BOOST_CHECK(!IsValidDestinationString(tensor_address));
        
        SelectParams(ChainType::TESTNET);
        BOOST_CHECK(!IsValidDestinationString(tensor_address));
        
        SelectParams(ChainType::REGTEST);
        BOOST_CHECK(!IsValidDestinationString(tensor_address));
    }
    
    // Test WIF key cross-network rejection
    {
        SelectParams(ChainType::MAIN);
        std::string btc_wif = EncodeSecret(key);
        
        // Should decode on Bitcoin mainnet
        BOOST_CHECK(DecodeSecret(btc_wif).IsValid());
        
        // Should NOT decode on Tensor networks
        SelectParams(ChainType::TENSOR_MAIN);
        BOOST_CHECK(!DecodeSecret(btc_wif).IsValid());
        
        SelectParams(ChainType::TENSOR_TEST);
        BOOST_CHECK(!DecodeSecret(btc_wif).IsValid());
    }
    
    // Test Bech32 address cross-network rejection
    {
        SelectParams(ChainType::MAIN);
        CTxDestination btc_witness = WitnessV0KeyHash(pubkey);
        std::string btc_bech32 = EncodeDestination(btc_witness);
        
        // Should start with "bc1"
        BOOST_CHECK(btc_bech32.substr(0, 3) == "bc1");
        BOOST_CHECK(IsValidDestinationString(btc_bech32));
        
        // Should NOT decode on Tensor networks  
        SelectParams(ChainType::TENSOR_MAIN);
        BOOST_CHECK(!IsValidDestinationString(btc_bech32));
        
        // Create Tensor bech32 address
        CTxDestination tensor_witness = WitnessV0KeyHash(pubkey);
        std::string tensor_bech32 = EncodeDestination(tensor_witness);
        
        // Should start with "tc1" 
        BOOST_CHECK(tensor_bech32.substr(0, 3) == "tc1");
        BOOST_CHECK(IsValidDestinationString(tensor_bech32));
        
        // Should NOT decode on Bitcoin
        SelectParams(ChainType::MAIN);
        BOOST_CHECK(!IsValidDestinationString(tensor_bech32));
    }
}

// Test that Tensor network addresses use correct prefixes
BOOST_AUTO_TEST_CASE(tensor_address_prefixes)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    
    // TensorMain addresses
    {
        SelectParams(ChainType::TENSOR_MAIN);
        
        // P2PKH should start with specific character (prefix 0x42)
        CTxDestination p2pkh = PKHash(pubkey);
        std::string p2pkh_addr = EncodeDestination(p2pkh);
        BOOST_CHECK(p2pkh_addr[0] == 'T' || p2pkh_addr[0] == 'U'); // Base58 for 0x42
        
        // P2SH should use TensorMain SCRIPT_ADDRESS version (0x13). Verify
        // version byte rather than first glyph which is not guaranteed.
        CScript script = GetScriptForDestination(p2pkh);
        CTxDestination p2sh = ScriptHash(script);
        std::string p2sh_addr = EncodeDestination(p2sh);
        std::vector<unsigned char> raw;
        BOOST_REQUIRE(DecodeBase58Check(p2sh_addr, raw, 255));
        BOOST_REQUIRE(!raw.empty());
        BOOST_CHECK_EQUAL(raw[0], 0x13);
        
        // Bech32 should start with "tc1"
        CTxDestination witness = WitnessV0KeyHash(pubkey);
        std::string bech32_addr = EncodeDestination(witness);
        BOOST_CHECK(bech32_addr.substr(0, 3) == "tc1");
    }
    
    // TensorTest addresses
    {
        SelectParams(ChainType::TENSOR_TEST);
        
        // Bech32 should start with "tct1"
        CTxDestination witness = WitnessV0KeyHash(pubkey);
        std::string bech32_addr = EncodeDestination(witness);
        BOOST_CHECK(bech32_addr.substr(0, 4) == "tct1");
    }
    
    // TensorReg addresses
    {
        SelectParams(ChainType::TENSOR_REG);
        
        // Bech32 should start with "tcrt1"
        CTxDestination witness = WitnessV0KeyHash(pubkey);
        std::string bech32_addr = EncodeDestination(witness);
        BOOST_CHECK(bech32_addr.substr(0, 5) == "tcrt1");
    }
}

BOOST_AUTO_TEST_SUITE_END()
