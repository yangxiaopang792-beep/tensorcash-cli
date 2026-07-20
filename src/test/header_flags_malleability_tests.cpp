// Tests for header flags malleability tolerance (flags do not affect PoW)

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <pow.h>

// Use RegTestingSetup to avoid any heavy VDF generation and ensure a clean
// regtest chain context for block construction.
BOOST_FIXTURE_TEST_SUITE(header_flags_malleability_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(pow_independent_of_header_flags)
{
    // Build a valid block
    CBlock block = CreateTensorBlock(m_node);

    // Verify PoW against short hash succeeds
    const auto& cons = Params().GetConsensus();
    BOOST_CHECK(CheckProofOfWork(block.GetShortHash(), block.nAdjBits, cons));

    // Mutate flags (these are not part of short-hash serialization)
    CBlock mutated = block;
    mutated.flags = 0xFF;

    // Short hash (PoW) must be unchanged, so PoW remains valid
    BOOST_CHECK_EQUAL(block.GetShortHash().ToString(), mutated.GetShortHash().ToString());
    BOOST_CHECK(CheckProofOfWork(mutated.GetShortHash(), mutated.nAdjBits, cons));
}

BOOST_AUTO_TEST_SUITE_END()
