// Explicit tests for PoW behavior against nAdjBits (independent of nBits)

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <arith_uint256.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>

BOOST_FIXTURE_TEST_SUITE(pow_adjbits_behavior_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(nbits_changes_do_not_help_pow)
{
    // Start from a solved block
    CBlock blk = CreateTensorBlock(m_node);
    const uint32_t adj_orig = blk.nAdjBits;
    const uint32_t nbits_orig = blk.nBits;
    const auto& cons = Params().GetConsensus();

    // PoW pass/fail MUST be independent of nBits when nAdjBits is fixed
    const bool pass_orig = CheckProofOfWork(blk.GetShortHash(), adj_orig, cons);

    CBlock mutated = blk;
    mutated.nBits = nbits_orig - 1; // harder network difficulty
    BOOST_CHECK_EQUAL(pass_orig, CheckProofOfWork(mutated.GetShortHash(), adj_orig, cons));

    mutated.nBits = nbits_orig + 1; // easier network difficulty
    BOOST_CHECK_EQUAL(pass_orig, CheckProofOfWork(mutated.GetShortHash(), adj_orig, cons));

    // Now show that tightening nAdjBits eventually makes PoW fail (deterministically by repeated halving)
    auto base = DeriveTarget(adj_orig, cons.powLimit);
    BOOST_REQUIRE(base);
    arith_uint256 t = *base;
    bool became_false = false;
    for (int i = 0; i < 256; ++i) {
        t /= arith_uint256(2);
        uint32_t compact = t.GetCompact();
        if (!CheckProofOfWork(blk.GetShortHash(), compact, cons)) { became_false = true; break; }
    }
    BOOST_CHECK(became_false);
}

BOOST_AUTO_TEST_CASE(adjbits_relaxation_enables_pow)
{
    // Create a solved block, then make target stricter to fail, then relax to pass
    CBlock blk = CreateTensorBlock(m_node);
    const auto& cons = Params().GetConsensus();
    const uint32_t adj_orig = blk.nAdjBits;

    // Stricter than solved target -> ensure failure by halving until fail, then relax one step to pass
    CBlock test = blk;
    auto base = DeriveTarget(adj_orig, cons.powLimit);
    BOOST_REQUIRE(base);
    arith_uint256 t = *base;
    bool found_fail = false;
    for (int i = 0; i < 256; ++i) {
        t /= arith_uint256(2);
        test.nAdjBits = t.GetCompact();
        if (!CheckProofOfWork(test.GetShortHash(), test.nAdjBits, cons)) { found_fail = true; break; }
    }
    BOOST_CHECK(found_fail);
    // Relax by doubling once and expect pass (with powLimit clamp)
    arith_uint256 powlim = UintToArith256(cons.powLimit);
    t *= arith_uint256(2);
    if (t > powlim) t = powlim;
    test.nAdjBits = t.GetCompact();
    BOOST_CHECK(CheckProofOfWork(test.GetShortHash(), test.nAdjBits, cons));
}

BOOST_AUTO_TEST_SUITE_END()
