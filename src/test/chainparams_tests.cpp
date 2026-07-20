// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <vector>

BOOST_AUTO_TEST_SUITE(chainparams_tests)

/**
 * Test that all networks have unique parameters to prevent overlap/replay attacks
 */
BOOST_AUTO_TEST_CASE(network_uniqueness)
{
    // Get all network parameters
    std::vector<std::unique_ptr<const CChainParams>> networks;
    networks.push_back(CChainParams::Main());
    networks.push_back(CChainParams::TestNet());
    networks.push_back(CChainParams::TestNet4());
    networks.push_back(CChainParams::RegTest({}));
    networks.push_back(CChainParams::SigNet({}));
    networks.push_back(CChainParams::TensorMain());
    networks.push_back(CChainParams::TensorTest());
    networks.push_back(CChainParams::TensorReg({}));

    // Check message start bytes are unique
    std::set<std::string> message_starts;
    for (const auto& network : networks) {
        auto msg_start = network->MessageStart();
        std::string msg_str(msg_start.begin(), msg_start.end());
        BOOST_CHECK_MESSAGE(
            message_starts.insert(msg_str).second,
            "Duplicate message start bytes found for network: " + ChainTypeToString(network->GetChainType())
        );
    }

    // Check Bech32 HRPs are unique
    std::set<std::string> hrps;
    for (const auto& network : networks) {
        const std::string& hrp = network->Bech32HRP();
        BOOST_CHECK_MESSAGE(
            hrps.insert(hrp).second,
            "Duplicate Bech32 HRP '" + hrp + "' found for network: " + ChainTypeToString(network->GetChainType())
        );
    }

    // Check Base58 prefixes are unique (P2PKH, P2SH, WIF)
    std::set<unsigned char> p2pkh_prefixes;
    std::set<unsigned char> p2sh_prefixes;
    std::set<unsigned char> wif_prefixes;
    
    for (const auto& network : networks) {
        auto p2pkh = network->Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        auto p2sh = network->Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        auto wif = network->Base58Prefix(CChainParams::SECRET_KEY);
        
        if (!p2pkh.empty()) {
            BOOST_CHECK_MESSAGE(
                p2pkh_prefixes.insert(p2pkh[0]).second,
                "Duplicate P2PKH prefix found for network: " + ChainTypeToString(network->GetChainType())
            );
        }
        
        if (!p2sh.empty()) {
            BOOST_CHECK_MESSAGE(
                p2sh_prefixes.insert(p2sh[0]).second,
                "Duplicate P2SH prefix found for network: " + ChainTypeToString(network->GetChainType())
            );
        }
        
        if (!wif.empty()) {
            BOOST_CHECK_MESSAGE(
                wif_prefixes.insert(wif[0]).second,
                "Duplicate WIF prefix found for network: " + ChainTypeToString(network->GetChainType())
            );
        }
    }

    // Check BIP32 extended key version bytes are unique
    std::set<std::vector<unsigned char>> xpub_versions;
    std::set<std::vector<unsigned char>> xprv_versions;
    
    for (const auto& network : networks) {
        auto xpub = network->Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        auto xprv = network->Base58Prefix(CChainParams::EXT_SECRET_KEY);
        
        BOOST_CHECK_MESSAGE(
            xpub_versions.insert(xpub).second,
            "Duplicate BIP32 xpub version found for network: " + ChainTypeToString(network->GetChainType())
        );
        
        BOOST_CHECK_MESSAGE(
            xprv_versions.insert(xprv).second,
            "Duplicate BIP32 xprv version found for network: " + ChainTypeToString(network->GetChainType())
        );
    }

    // Check network ports are unique
    std::set<uint16_t> ports;
    for (const auto& network : networks) {
        uint16_t port = network->GetDefaultPort();
        BOOST_CHECK_MESSAGE(
            ports.insert(port).second,
            "Duplicate network port " + std::to_string(port) + " found for network: " + ChainTypeToString(network->GetChainType())
        );
    }
}

/**
 * Test genesis block consistency for Tensor networks
 */
BOOST_AUTO_TEST_CASE(tensor_genesis_consistency)
{
    // TensorMain genesis checks
    auto tensor_main = CChainParams::TensorMain();
    const auto& tm_genesis = tensor_main->GenesisBlock();
    BOOST_CHECK(tm_genesis.GetHash() == tensor_main->GetConsensus().hashGenesisBlock);
    BOOST_CHECK(tm_genesis.GetShortHash() == tensor_main->GetConsensus().hashGenesisBlockShort);
    BOOST_CHECK(!tm_genesis.hashMerkleRoot.IsNull());
    
    // TensorTest genesis checks  
    auto tensor_test = CChainParams::TensorTest();
    const auto& tt_genesis = tensor_test->GenesisBlock();
    BOOST_CHECK(tt_genesis.GetHash() == tensor_test->GetConsensus().hashGenesisBlock);
    BOOST_CHECK(tt_genesis.GetShortHash() == tensor_test->GetConsensus().hashGenesisBlockShort);
    BOOST_CHECK(!tt_genesis.hashMerkleRoot.IsNull());
    
    // TensorReg genesis checks
    auto tensor_reg = CChainParams::TensorReg({});
    const auto& tr_genesis = tensor_reg->GenesisBlock();
    BOOST_CHECK(tr_genesis.GetHash() == tensor_reg->GetConsensus().hashGenesisBlock);
    BOOST_CHECK(tr_genesis.GetShortHash() == tensor_reg->GetConsensus().hashGenesisBlockShort);
    BOOST_CHECK(!tr_genesis.hashMerkleRoot.IsNull());
    
    // Ensure all Tensor genesis blocks are different
    BOOST_CHECK(tm_genesis.GetHash() != tt_genesis.GetHash());
    BOOST_CHECK(tm_genesis.GetHash() != tr_genesis.GetHash());
    BOOST_CHECK(tt_genesis.GetHash() != tr_genesis.GetHash());
}

/**
 * Test that Tensor network parameters match specification
 */
BOOST_AUTO_TEST_CASE(tensor_network_parameters)
{
    // TensorMain checks
    auto tensor_main = CChainParams::TensorMain();
    BOOST_CHECK_EQUAL(tensor_main->GetDefaultPort(), 39241);
    BOOST_CHECK_EQUAL(tensor_main->Bech32HRP(), "tc");
    BOOST_CHECK_EQUAL(tensor_main->Base58Prefix(CChainParams::PUBKEY_ADDRESS)[0], 0x42);
    BOOST_CHECK_EQUAL(tensor_main->Base58Prefix(CChainParams::SCRIPT_ADDRESS)[0], 0x13);
    BOOST_CHECK_EQUAL(tensor_main->Base58Prefix(CChainParams::SECRET_KEY)[0], 0xD2);
    
    // TensorTest checks
    auto tensor_test = CChainParams::TensorTest();
    BOOST_CHECK_EQUAL(tensor_test->GetDefaultPort(), 29241);
    BOOST_CHECK_EQUAL(tensor_test->Bech32HRP(), "tct");
    BOOST_CHECK_EQUAL(tensor_test->Base58Prefix(CChainParams::PUBKEY_ADDRESS)[0], 0x43);
    BOOST_CHECK_EQUAL(tensor_test->Base58Prefix(CChainParams::SCRIPT_ADDRESS)[0], 0x14);
    BOOST_CHECK_EQUAL(tensor_test->Base58Prefix(CChainParams::SECRET_KEY)[0], 0xE2);
    
    // TensorReg checks
    auto tensor_reg = CChainParams::TensorReg({});
    BOOST_CHECK_EQUAL(tensor_reg->GetDefaultPort(), 19241);
    BOOST_CHECK_EQUAL(tensor_reg->Bech32HRP(), "tcrt");
    BOOST_CHECK_EQUAL(tensor_reg->Base58Prefix(CChainParams::PUBKEY_ADDRESS)[0], 0x44);
    BOOST_CHECK_EQUAL(tensor_reg->Base58Prefix(CChainParams::SCRIPT_ADDRESS)[0], 0x15);
    BOOST_CHECK_EQUAL(tensor_reg->Base58Prefix(CChainParams::SECRET_KEY)[0], 0xF2);
}

BOOST_AUTO_TEST_SUITE_END()