// Ensure tick accumulation is undone on reorg

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vdf/VdfGenerate.h>

using node::RegenerateCommitments;

struct TensorRegSetup : public TestingSetup { TensorRegSetup(): TestingSetup{ChainType::TENSOR_REG} {} };

BOOST_FIXTURE_TEST_SUITE(tick_reorg_tests, TensorRegSetup)

BOOST_AUTO_TEST_CASE(ticks_undone_on_reorg)
{
    // Baseline: tensor-reg genesis carries an embedded VDF proof (tick=10,
    // mirroring regtest), so derive the starting cumulative from genesis
    // instead of assuming 0.
    const uint64_t base_cum = Params().GenesisBlock().cumulative_tick;

    // Accept first block with certain tick
    CBlock b1 = CreateTensorBlock(m_node);
    b1.pow.tick = 100;
    // Regenerate VDF proof for the new tick value
    b1.pow.vdf = vdf::GenerateProofForTesting(b1.hashPrevBlock, b1.pow.tick, 1024);
    b1.hashPoW = b1.pow.GetCommitment(true);
    // cumulative_tick = prev(genesis)+tick
    b1.cumulative_tick = base_cum + 100;
    RegenerateCommitments(b1, *Assert(m_node.chainman));
    auto p1 = std::make_shared<const CBlock>(b1);
    bool nb{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(p1, true, true, &nb));

    // Accept second block with additional tick
    CBlock b2 = CreateTensorBlock(m_node);
    b2.pow.tick = 250;
    // Regenerate VDF proof for the new tick value
    b2.pow.vdf = vdf::GenerateProofForTesting(b2.hashPrevBlock, b2.pow.tick, 1024);
    b2.hashPoW = b2.pow.GetCommitment(true);
    // cumulative = prev.cum + 250
    const CBlockIndex* tip1 = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    CBlock prev; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(prev, *tip1));
    b2.cumulative_tick = prev.cumulative_tick + 250;
    RegenerateCommitments(b2, *Assert(m_node.chainman));
    auto p2 = std::make_shared<const CBlock>(b2);
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(p2, true, true, &nb));

    // Record cumulative at tip
    const CBlockIndex* tip2 = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    CBlock tipb; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(tipb, *tip2));
    const uint64_t cum_after = tipb.cumulative_tick;
    BOOST_CHECK_EQUAL(cum_after, base_cum + 350);

    // Invalidate tip and ensure cumulative reverts
    BlockValidationState s;
    BOOST_CHECK(Assert(m_node.chainman)->ActiveChainstate().InvalidateBlock(s, const_cast<CBlockIndex*>(tip2)));
    const CBlockIndex* tip_after = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    CBlock tipb_after; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(tipb_after, *tip_after));
    BOOST_CHECK_EQUAL(tipb_after.cumulative_tick, base_cum + 100);
}

BOOST_AUTO_TEST_SUITE_END()

