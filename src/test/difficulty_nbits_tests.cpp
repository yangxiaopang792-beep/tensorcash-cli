// Tests that network retargeting uses nBits (not nAdjBits)

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>

// Use RegTestingSetup to avoid mutating global params mid-suite and to
// provide a ready regtest environment
BOOST_FIXTURE_TEST_SUITE(difficulty_nbits_tests, RegTestingSetup)

// GetNextWorkRequired must be independent of nAdjBits
BOOST_AUTO_TEST_CASE(getnextwork_ignores_nadjbits)
{
    // Mine one block so we have a tip
    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    // Prepare a header building on the tip
    CBlockHeader probe;
    probe.nVersion = 1;
    probe.hashPrevBlock = base.GetHash();
    probe.hashMerkleRoot.SetNull();
    probe.nTime = base.nTime + 1;
    probe.nBits = base.nBits;   // start with same network nBits
    probe.nAdjBits = base.nAdjBits; // arbitrary value
    probe.nNonce = 0;
    probe.hashPoW.SetNull();
    probe.flags = 0;

    const auto& cons = Params().GetConsensus();
    const CBlockIndex* pprev = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    BOOST_REQUIRE(pprev);

    unsigned int nbits_a = GetNextWorkRequired(pprev, &probe, cons);

    // Mutate nAdjBits and recompute
    probe.nAdjBits = probe.nBits - 1; // make it different
    unsigned int nbits_b = GetNextWorkRequired(pprev, &probe, cons);

    // Retarget must not depend on nAdjBits
    BOOST_CHECK_EQUAL(nbits_a, nbits_b);
}

// Contextual check must reject when header.nBits != GetNextWorkRequired(...)
BOOST_AUTO_TEST_CASE(bad_diffbits_rejected)
{
    // Accept a valid tip block first
    CBlock good = CreateTensorBlock(m_node);
    auto goodptr = std::make_shared<const CBlock>(good);
    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(goodptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    // Build another valid block template, then mutate nBits (network difficulty)
    CBlock bad = CreateTensorBlock(m_node);
    // Flip nBits to an incorrect value while keeping nAdjBits (PoW check uses nAdjBits)
    bad.nBits = bad.nBits - 1;
    // Keep commitments consistent
    node::RegenerateCommitments(bad, *Assert(m_node.chainman));
    UpdateTestBlockVdf(bad, *Assert(m_node.chainman));

    // Process and expect contextual header rejection due to bad-diffbits
    auto badptr = std::make_shared<const CBlock>(bad);
    bool ignored{false};
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(badptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));

    // Tip must remain unchanged
    const uint256 tip_after = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash());
    BOOST_CHECK_EQUAL(tip_after.ToString(), good.GetHash().ToString());
}

BOOST_AUTO_TEST_SUITE_END()
