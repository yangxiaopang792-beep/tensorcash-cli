// Test to dump actual genesis block values for updating chainparams.cpp
// Run: test_bitcoin --run_test=genesis_values_dump/dump_regtest_genesis_values

#include <boost/test/unit_test.hpp>
#include <chainparams.h>
#include <kernel/chainparams.h>
#include <kernel/coinstats.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>
#include <vdf/VdfGenerate.h>

#include <iostream>
#include <iomanip>

BOOST_AUTO_TEST_SUITE(genesis_values_dump)

BOOST_FIXTURE_TEST_CASE(dump_regtest_genesis_values, RegTestingSetup)
{
    using namespace std;

    cout << "\n==============================================\n";
    cout << "REGTEST GENESIS BLOCK ACTUAL VALUES\n";
    cout << "==============================================\n\n";

    // Get the genesis block
    const CBlock& genesis = Params().GenesisBlock();

    // Dump all the key values
    cout << "Genesis Block Time: " << genesis.nTime << "\n";
    cout << "Genesis Block Nonce: " << genesis.nNonce << "\n";
    cout << "Genesis Block Bits: 0x" << hex << genesis.nBits << dec << "\n";
    cout << "Genesis Block AdjBits: 0x" << hex << genesis.nAdjBits << dec << "\n";
    cout << "Genesis Block Version: " << genesis.nVersion << "\n";
    cout << "\n";

    cout << "Genesis PoW tick: " << genesis.pow.tick << "\n";
    cout << "Genesis cumulative_tick: " << genesis.cumulative_tick << "\n";
    cout << "Genesis PoW model_identifier: \"" << genesis.pow.model_identifier << "\"\n";
    cout << "\n";

    // VDF proof bytes
    cout << "Genesis PoW VDF size: " << genesis.pow.vdf.size() << " bytes\n";
    if (!genesis.pow.vdf.empty()) {
        cout << "Genesis PoW VDF hex: " << HexStr(genesis.pow.vdf) << "\n";
        cout << "\nGenesis PoW VDF as C++ array:\n";
        cout << "genesis.pow.vdf = {\n    ";
        for (size_t i = 0; i < genesis.pow.vdf.size(); ++i) {
            cout << "0x" << hex << setw(2) << setfill('0') << (unsigned)genesis.pow.vdf[i] << dec;
            if (i + 1 != genesis.pow.vdf.size()) cout << ", ";
            if ((i + 1) % 16 == 0 && i + 1 != genesis.pow.vdf.size()) cout << "\n    ";
        }
        cout << "\n};\n";
    }
    cout << "\n";

    // Compute and display hashes
    uint256 hashMerkleRoot = genesis.hashMerkleRoot;
    uint256 hashPoW = genesis.hashPoW;
    uint256 hashGenesisBlock = genesis.GetHash();
    uint256 hashGenesisBlockShort = genesis.GetShortHash();

    cout << "COMPUTED HASHES:\n";
    cout << "================\n";
    cout << "hashMerkleRoot: " << hashMerkleRoot.ToString() << "\n";
    cout << "hashPoW: " << hashPoW.ToString() << "\n";
    cout << "hashGenesisBlock (full): " << hashGenesisBlock.ToString() << "\n";
    cout << "hashGenesisBlockShort: " << hashGenesisBlockShort.ToString() << "\n";
    cout << "\n";

    // Display what the assertions should be
    cout << "CODE TO UPDATE IN chainparams.cpp (CRegTestParams constructor):\n";
    cout << "================================================================\n";
    cout << "// After CreateGenesisBlock line:\n";
    cout << "genesis.pow.tick = " << genesis.pow.tick << ";\n";
    if (!genesis.pow.vdf.empty()) {
        cout << "genesis.pow.vdf = {\n    ";
        for (size_t i = 0; i < genesis.pow.vdf.size(); ++i) {
            cout << "0x" << hex << setw(2) << setfill('0') << (unsigned)genesis.pow.vdf[i] << dec;
            if (i + 1 != genesis.pow.vdf.size()) cout << ", ";
            if ((i + 1) % 16 == 0 && i + 1 != genesis.pow.vdf.size()) cout << " \n    ";
        }
        cout << "\n};\n";
    }
    cout << "genesis.cumulative_tick = genesis.pow.tick;\n";
    cout << "genesis.hashPoW = genesis.pow.GetCommitment(true);\n";
    cout << "consensus.hashGenesisBlock = genesis.GetHash();\n";
    cout << "consensus.hashGenesisBlockShort = genesis.GetShortHash();\n";
    cout << "\n";
    cout << "// Update assertions:\n";
    cout << "assert(genesis.hashMerkleRoot == uint256{\"" << hashMerkleRoot.ToString() << "\"});\n";
    cout << "assert(consensus.hashGenesisBlockShort == uint256{\"" << hashGenesisBlockShort.ToString() << "\"});\n";
    cout << "// If you need to assert hashPoW:\n";
    cout << "assert(genesis.hashPoW == uint256{\"" << hashPoW.ToString() << "\"});\n";

    cout << "\n==============================================\n\n";

    // This test always passes - it's just for dumping values
    BOOST_CHECK(true);
}

BOOST_FIXTURE_TEST_CASE(dump_regtest_assumeutxo_values, RegTestingSetup)
{
    using namespace std;

    cout << "\n==============================================\n";
    cout << "REGTEST ASSUMEUTXO VALUES FOR CHAINPARAMS\n";
    cout << "==============================================\n\n";

    auto& chainman = *Assert(m_node.chainman);
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
            if (!idx) {
                cout << "// Height " << height << " not yet mined\n";
                return;
            }
        }
        // Ensure DB best block is at requested height and compute stats
        auto stats = dump_stats_at_tip();
        cout << "{\n";
        cout << "    .height = " << idx->nHeight << ",\n";
        cout << "    .hash_serialized = AssumeutxoHash{uint256{\"" << stats.hashSerialized.ToString() << "\"}},\n";
        cout << "    .m_chain_tx_count = " << idx->m_chain_tx_count << ",\n";
        cout << "    .blockhash = consteval_ctor(uint256{\"" << idx->GetBlockHash().ToString() << "\"}),\n";
        cout << "},\n";
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
            auto block = PrepareBlock(m_node, scriptPubKey);
            MineBlock(m_node, block);
        }
    };

    cout << "m_assumeutxo_data = {\n";

    // Mine to and dump values for heights 100, 110, 200, 299
    mine_to(100);
    print_entry_for_height(100);

    mine_to(110);
    print_entry_for_height(110);

    mine_to(200);
    print_entry_for_height(200);

    mine_to(299);
    print_entry_for_height(299);

    cout << "};\n";
    cout << "\n==============================================\n\n";

    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()