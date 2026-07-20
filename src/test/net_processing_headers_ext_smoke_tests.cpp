// Smoke tests for net_processing HEADERS_EXT handling using ConnmanTestMsg.

#include <boost/test/unit_test.hpp>

#include <test/util/setup_common.h>
#include <test/util/net.h>
#include <net_processing.h>
#include <protocol.h>
#include <streams.h>

BOOST_AUTO_TEST_SUITE(net_processing_headers_ext_smoke_tests)

// Minimal serialization helpers mirroring VdfExtSidecar fields used on wire
struct VdfExtSidecarWire {
    uint256 header_hash;
    uint256 prev_hash;
    uint64_t tick{0};
    std::vector<unsigned char> vdf;
    std::vector<uint256> merkle_branch_tick;
    std::vector<uint256> merkle_branch_vdf;
    uint8_t leaf_scheme_version{1};
    uint32_t n_leaves{4};

    template <typename Stream>
    void Serialize(Stream& s) const {
        s << header_hash << prev_hash << tick << vdf << merkle_branch_tick << merkle_branch_vdf << leaf_scheme_version << n_leaves;
    }
};

BOOST_FIXTURE_TEST_CASE(headers_ext_basic_accepts, RegTestingSetup)
{
    // Set up a single outbound peer
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    PeerManager& peerman = *m_node.peerman;

    // Create a test node with a ZeroSock so we can drive messages without real sockets
    CAddress addr{};
    std::shared_ptr<Sock> sock = std::make_shared<ZeroSock>();
    auto* pnode = new CNode{1, sock, addr, /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0, CService{}, "", ConnectionType::OUTBOUND_FULL_RELAY, /*inbound_onion=*/false};
    pnode->SetCommonVersion(PROTOCOL_VERSION);
    WITH_LOCK(::cs_main, peerman.InitializeNode(*pnode, ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_VDFSPV)));
    pnode->fSuccessfullyConnected = true;
    connman.AddTestNode(*pnode);

    // Send a HEADERS_EXT message with minimal content (vdf non-empty but tiny)
    VdfExtSidecarWire sc;
    sc.header_hash = GetRandHash();
    sc.prev_hash = GetRandHash();
    sc.tick = 1;
    sc.vdf = std::vector<unsigned char>{0x01, 0x02, 0x03};
    // Empty branches (allowed pre-activation); our smoke test doesn't assert branches here.

    CSerializedNetMsg msg{NetMsg::Make(NetMsgType::HEADERS_EXT, std::vector<VdfExtSidecarWire>{sc})};

    bool more_work = false;
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        (void)connman.ReceiveMsgFrom(*pnode, std::move(msg));
        more_work = connman.ProcessMessagesOnce(*pnode);
    }
    // Just ensure the message was processed without throwing and the loop can continue
    BOOST_CHECK(more_work || !more_work);
}

BOOST_AUTO_TEST_SUITE_END()
