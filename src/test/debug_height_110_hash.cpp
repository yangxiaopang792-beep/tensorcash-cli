// Debug test to generate correct assumeutxo values for TestChain100Setup
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <chainparams.h>
#include <kernel/coinstats.h>
#include <node/chainstate.h>
#include <validation.h>
#include <iostream>

BOOST_AUTO_TEST_SUITE(debug_height_110)

// Compute UTXO stats at current tip
static kernel::CCoinsStats ComputeUTXOStatsAtTip(node::NodeContext& node) {
    auto& chainman = *Assert(node.chainman);
    auto& chainstate = chainman.ActiveChainstate();
    {
        LOCK(cs_main);
        chainstate.ForceFlushStateToDisk();
    }
    auto stats_opt = kernel::ComputeUTXOStats(kernel::CoinStatsHashType::HASH_SERIALIZED,
                                              &chainstate.CoinsDB(), chainman.m_blockman);
    assert(stats_opt.has_value());
    return *stats_opt;
}

BOOST_FIXTURE_TEST_CASE(dump_testchain100_assumeutxo, TestChain100Setup)
{
    using namespace std;

    cout << "\n=== ASSUMEUTXO VALUES FOR TestChain100Setup ===\n\n";

    // Mine to and dump each height that tests use
    auto dump_height = [&](int target_height) {
        // Mine to target if needed
        {
            LOCK(::cs_main);
            int current = m_node.chainman->ActiveChain().Height();
            if (current < target_height) {
                mineBlocks(target_height - current);
            }
        }

        // Get stats
        auto stats = ComputeUTXOStatsAtTip(m_node);
        const CBlockIndex* idx = nullptr;
        {
            LOCK(::cs_main);
            idx = m_node.chainman->ActiveChain()[target_height];
        }

        cout << "{\n";
        cout << "    .height = " << target_height << ",\n";
        cout << "    .hash_serialized = AssumeutxoHash{uint256{\"" << stats.hashSerialized.ToString() << "\"}},\n";
        cout << "    .m_chain_tx_count = " << idx->m_chain_tx_count << ",\n";
        cout << "    .blockhash = consteval_ctor(uint256{\"" << idx->GetBlockHash().ToString() << "\"}),\n";
        cout << "},\n";
    };

    cout << "m_assumeutxo_data = {\n";
    dump_height(100);
    dump_height(110);
    dump_height(200);
    dump_height(299);
    cout << "};\n\n";

    cout << "================================================\n\n";

    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()