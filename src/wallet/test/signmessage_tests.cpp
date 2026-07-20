// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/wallet.h>

#include <key_io.h>
#include <node/context.h>
#include <outputtype.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/check.h>
#include <util/result.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <stdexcept>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(signmessage_tests, WalletTestingSetup)

static UniValue CallRPC(const std::string& method, const UniValue& params, const std::string& uri, node::NodeContext& node)
{
    JSONRPCRequest request;
    request.context = &node;
    request.strMethod = method;
    request.params = params;
    request.URI = uri;
    if (RPCIsInWarmup(nullptr)) {
        SetRPCWarmupFinished();
    }
    try {
        return tableRPC.execute(request);
    } catch (const UniValue& e) {
        throw std::runtime_error(e.write());
    }
}

BOOST_AUTO_TEST_CASE(bip322_roundtrip)
{
    const std::string message{"test governance attestation"};
    std::string address;
    std::string signature;
    std::string sign_error;
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();

        auto dest = m_wallet.GetNewDestination(OutputType::BECH32M, "");
        BOOST_REQUIRE(dest);
        address = EncodeDestination(*dest);

        bool sign_result = m_wallet.SignMessageBIP322(address, message, signature, sign_error);
        BOOST_REQUIRE(sign_result);
        BOOST_CHECK(sign_error.empty());
        BOOST_CHECK(!signature.empty());
    }

    UniValue verify_params(UniValue::VARR);
    verify_params.push_back(address);
    verify_params.push_back(signature);
    verify_params.push_back(message);
    UniValue verify_result = CallRPC("verifymessagebip322", verify_params, "/", m_node);
    BOOST_CHECK(verify_result.get_bool());
}

BOOST_AUTO_TEST_CASE(rpc_signmessagebip322)
{
    const std::string message{"hello rpc"};
    std::string address;
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();

        auto dest = m_wallet.GetNewDestination(OutputType::BECH32, "");
        BOOST_REQUIRE(dest);
        address = EncodeDestination(*dest);
    }

    UniValue params(UniValue::VARR);
    params.push_back(address);
    params.push_back(message);
    std::string wallet_uri = "/";
    UniValue signature = CallRPC("signmessagebip322", params, wallet_uri, m_node);
    BOOST_CHECK(signature.isStr());

    UniValue verify_params(UniValue::VARR);
    verify_params.push_back(address);
    verify_params.push_back(signature.get_str());
    verify_params.push_back(message);
    UniValue verify_result = CallRPC("verifymessagebip322", verify_params, "/", m_node);
    BOOST_CHECK(verify_result.get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
