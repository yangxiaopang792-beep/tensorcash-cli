// Utility test that prints a paste-ready regtest genesis VDF snippet.
// Run: test_bitcoin --run_test=genesis_debug_tools

#include <boost/test/unit_test.hpp>
#include <kernel/chainparams.h>
#include <kernel/coinstats.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <script/script.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>
#include <vdf/VdfGenerate.h>

#include <iomanip>
#include <iostream>

static void print_hex_list(const std::vector<uint8_t>& v, size_t per_line = 16)
{
    std::cout << "{\n    ";
    for (size_t i = 0; i < v.size(); ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned)v[i] << std::dec;
        if (i + 1 != v.size()) std::cout << ", ";
        if ((i + 1) % per_line == 0 && i + 1 != v.size()) std::cout << "\n    ";
    }
    std::cout << "\n}";
}

BOOST_AUTO_TEST_SUITE(genesis_debug_tools)

static void PrintAssumeUtxoEntry(const CBlockIndex* pindex, const kernel::CCoinsStats& stats)
{
    using std::cout;
    cout << "  {   // Auto-generated checkpoint\n";
    cout << "      .height = " << pindex->nHeight << ",\n";
    cout << "      .hash_serialized = AssumeutxoHash{uint256{\"" << stats.hashSerialized.ToString() << "\"}},\n";
    cout << "      .m_chain_tx_count = " << pindex->m_chain_tx_count << ",\n";
    cout << "      .blockhash = consteval_ctor(uint256{\"" << pindex->GetBlockHash().ToString() << "\"}),\n";
    cout << "  },\n";
}

BOOST_AUTO_TEST_CASE(genesis_debug_tools)
{
    using namespace std;
    cout << "=== Regtest Genesis VDF Snippet Generator ===\n";
    auto reg = CChainParams::RegTest({});
    CBlock g = reg->GenesisBlock();
    const uint64_t tick = 10; // minimal test tick
    vector<uint8_t> proof = vdf::GenerateProofForTesting(g.hashPrevBlock, tick, /*discr_bits=*/1024);
    if (proof.empty()) {
        cout << "Failed to generate VDF proof for regtest genesis" << endl;
        BOOST_CHECK_MESSAGE(false, "VDF proof generation failed");
        return;
    }

    g.pow.tick = tick;
    g.pow.vdf = proof;
    g.cumulative_tick = tick;
    g.hashPoW = g.pow.GetCommitment(/*use_merkle=*/true);

    cout << "\n// Paste into services/core-node/bcore/src/kernel/chainparams.cpp (regtest section)\n";
    cout << "genesis.pow.tick = " << tick << ";\n";
    cout << "genesis.pow.vdf = ";
    print_hex_list(proof);
    cout << ";\n";
    cout << "genesis.cumulative_tick = genesis.pow.tick;\n";
    cout << "genesis.hashPoW = uint256{\"" << g.hashPoW.ToString() << "\"};\n";
    cout << "consensus.hashGenesisBlock = uint256{\"" << g.GetHash().ToString() << "\"};\n";
    cout << "consensus.hashGenesisBlockShort = uint256{\"" << g.GetShortHash().ToString() << "\"};\n";

    // Keep test passing
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(assumeutxo_checkpoints)
{
    // Bring up a regtest chain and mine to heights 100, 110 and 299 deterministically
    RegTestingSetup setup;

    auto& chainman = *Assert(setup.m_node.chainman);
    auto& chainstate = chainman.ActiveChainstate();

    auto dump_stats_at_tip = [&]() -> kernel::CCoinsStats {
        // Flush coins cache to DB so CoinsDB bestblock is the tip we expect
        {
            LOCK(cs_main);
            chainstate.ForceFlushStateToDisk();
        }
        auto stats_opt = kernel::ComputeUTXOStats(kernel::CoinStatsHashType::HASH_SERIALIZED,
                                                  &chainstate.CoinsDB(), chainman.m_blockman);
        BOOST_REQUIRE_MESSAGE(stats_opt.has_value(), "ComputeUTXOStats failed");
        return *stats_opt;
    };

    auto print_entry_for_height = [&](int height) {
        const CBlockIndex* idx = nullptr;
        {
            LOCK(::cs_main);
            idx = chainman.ActiveChain()[height];
            BOOST_REQUIRE(idx != nullptr);
        }
        // Ensure DB best block is at requested height and compute stats
        auto stats = dump_stats_at_tip();
        // Recheck tip height matches expectation
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(chainman.ActiveChain().Tip()->nHeight == height);
        }
        PrintAssumeUtxoEntry(idx, stats);
    };

    // Helper: mine until the chain reaches target height
    auto mine_to = [&](int target_height) {
        CScript scriptPubKey = CScript() << OP_TRUE; // anyone-can-spend for testing
        while (true) {
            int cur_h;
            {
                LOCK(::cs_main);
                cur_h = chainman.ActiveChain().Height();
            }
            if (cur_h >= target_height) break;
            auto block = PrepareBlock(setup.m_node, scriptPubKey);
            MineBlock(setup.m_node, block);
        }
    };

    std::cout << "\n=== AssumeUTXO entries (paste into chainparams.cpp, regtest m_assumeutxo_data) ===\n";

    mine_to(100);
    print_entry_for_height(100);

    mine_to(110);
    print_entry_for_height(110);

    mine_to(299);
    print_entry_for_height(299);
}

BOOST_AUTO_TEST_SUITE_END()
