// Simple test to capture TensorReg tip hash at height 100 and genesis hash
#include <test/util/setup_common.h>
#include <chainparams.h>
#include <validation.h>
#include <primitives/block.h>
#include <boost/test/unit_test.hpp>
#include <iostream>

// Custom fixture that uses TENSOR_REG chain type
struct TensorRegTestChain100Setup : public TestChain100Setup {
    TensorRegTestChain100Setup() : TestChain100Setup(ChainType::TENSOR_REG) {}
};

// Custom fixture that uses TENSOR_MAIN chain type
struct TensorMainSetup : public BasicTestingSetup {
    TensorMainSetup() : BasicTestingSetup(ChainType::TENSOR_MAIN) {}
};

// Custom fixture that uses REGTEST chain type
struct RegTestChain100Setup : public TestChain100Setup {
    RegTestChain100Setup() : TestChain100Setup(ChainType::REGTEST) {}
};

BOOST_AUTO_TEST_SUITE(tensor_tip_tests)

BOOST_FIXTURE_TEST_CASE(get_tensor_reg_tip_100, TensorRegTestChain100Setup)
{
    auto tip = m_node.chainman->ActiveChain().Tip();
    auto genesis = m_node.chainman->ActiveChain()[0];

    std::cout << "\n=== TensorReg Genesis Block ===" << std::endl;
    std::cout << "Height: " << genesis->nHeight << std::endl;
    std::cout << "Hash: " << genesis->GetBlockHash().ToString() << std::endl;
    std::cout << "================================\n" << std::endl;

    std::cout << "=== TensorReg Tip at Height 100 ===" << std::endl;
    std::cout << "Height: " << tip->nHeight << std::endl;
    std::cout << "Hash: " << tip->GetBlockHash().ToString() << std::endl;
    std::cout << "ChainWork: " << tip->nChainWork.ToString() << std::endl;
    std::cout << "==================================\n" << std::endl;

    // Also output it in a format ready to paste into the test
    std::cout << "For TestChain100Setup assertion:" << std::endl;
    std::cout << "assert(tip_hash_str == \""
              << tip->GetBlockHash().ToString() << "\");" << std::endl;

    // Compute what the genesis hash WOULD be with new Merkle commitment
    const auto& params = Params();
    CBlock genesis_block = params.GenesisBlock();

    std::cout << "\n=== Genesis Block PoW Details ===" << std::endl;
    std::cout << "Original hashPoW: " << genesis_block.hashPoW.ToString() << std::endl;
    std::cout << "pow.GetHash(): " << genesis_block.pow.GetHash().ToString() << std::endl;
    std::cout << "pow.GetMerkleRoot(): " << genesis_block.pow.GetMerkleRoot().ToString() << std::endl;

    // Show what the genesis hash would be with Merkle commitment
    CBlock test_genesis = genesis_block;
    test_genesis.hashPoW = test_genesis.pow.GetMerkleRoot();
    std::cout << "Genesis hash with Merkle commitment: " << test_genesis.GetHash().ToString() << std::endl;
    std::cout << "==================================\n" << std::endl;
}

BOOST_FIXTURE_TEST_CASE(get_tensor_main_genesis, TensorMainSetup)
{
    const auto& params = Params();
    CBlock genesis_block = params.GenesisBlock();

    std::cout << "\n=== TensorMain (Mainnet) Genesis Block ===" << std::endl;
    std::cout << "Genesis Hash: " << params.GetConsensus().hashGenesisBlock.ToString() << std::endl;
    std::cout << "Genesis Short Hash: " << params.GetConsensus().hashGenesisBlockShort.ToString() << std::endl;
    std::cout << "================================\n" << std::endl;

    std::cout << "=== Genesis Block PoW Details ===" << std::endl;
    std::cout << "Original hashPoW: " << genesis_block.hashPoW.ToString() << std::endl;
    std::cout << "pow.GetHash(): " << genesis_block.pow.GetHash().ToString() << std::endl;
    std::cout << "pow.GetMerkleRoot(): " << genesis_block.pow.GetMerkleRoot().ToString() << std::endl;
    std::cout << "hashMerkleRoot: " << genesis_block.hashMerkleRoot.ToString() << std::endl;
    std::cout << "==================================\n" << std::endl;

    // Output ready-to-paste assertion
    std::cout << "For CTensorMainParams assertion:" << std::endl;
    std::cout << "assert(consensus.hashGenesisBlock == uint256{\""
              << params.GetConsensus().hashGenesisBlock.ToString() << "\"});" << std::endl;
}

BOOST_FIXTURE_TEST_CASE(get_regtest_tip_100, RegTestChain100Setup)
{
    auto tip = m_node.chainman->ActiveChain().Tip();
    auto genesis = m_node.chainman->ActiveChain()[0];

    std::cout << "\n=== RegTest Genesis Block ===" << std::endl;
    std::cout << "Height: " << genesis->nHeight << std::endl;
    std::cout << "Hash: " << genesis->GetBlockHash().ToString() << std::endl;
    std::cout << "================================\n" << std::endl;

    std::cout << "=== RegTest Tip at Height 100 ===" << std::endl;
    std::cout << "Height: " << tip->nHeight << std::endl;
    std::cout << "Hash: " << tip->GetBlockHash().ToString() << std::endl;
    std::cout << "ChainWork: " << tip->nChainWork.ToString() << std::endl;
    std::cout << "==================================\n" << std::endl;

    // Output ready-to-paste assertion
    std::cout << "For TestChain100Setup REGTEST assertion:" << std::endl;
    std::cout << "assert(tip_hash_str == \""
              << tip->GetBlockHash().ToString() << "\");" << std::endl;
}

// Fixture for getting block at height 110 for assumeutxo
struct RegTest110Setup : public TestChain100Setup {
    RegTest110Setup() : TestChain100Setup(ChainType::REGTEST) {
        // TestChain100Setup already mines 100 blocks, mine 10 more
        mineBlocks(10);
    }
};

BOOST_FIXTURE_TEST_CASE(get_regtest_110, RegTest110Setup)
{
    auto* tip = m_node.chainman->ActiveChain().Tip();

    std::cout << "\n=== RegTest Block at Height 110 ===" << std::endl;
    std::cout << "Height: " << tip->nHeight << std::endl;
    std::cout << "Hash: " << tip->GetBlockHash().ToString() << std::endl;
    std::cout << "==================================\n" << std::endl;

    // Output ready-to-paste for assumeutxo data
    std::cout << "For REGTEST assumeutxo_data at height 110:" << std::endl;
    std::cout << ".blockhash = consteval_ctor(uint256{\""
              << tip->GetBlockHash().ToString() << "\"})," << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
