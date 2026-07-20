// Verify chainwork is derived from nBits (not nAdjBits) using header work calculations.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <primitives/block.h>
#include <validation.h>
#include <test/util/setup_common.h>
#include <validation.h>

BOOST_FIXTURE_TEST_SUITE(chainwork_nbits_selection_tests, BasicTestingSetup)

// Build a simple header sequence with constant nBits but varied nAdjBits
static std::vector<CBlockHeader> MakeHeaders(unsigned count, uint32_t nBits, uint32_t nAdjBits)
{
    std::vector<CBlockHeader> v;
    v.reserve(count);
    uint256 prev; prev.SetNull();
    for (unsigned i = 0; i < count; ++i) {
        CBlockHeader h; h.SetNull();
        h.nVersion = 1;
        h.hashPrevBlock = (i == 0) ? uint256() : v.back().GetHash();
        h.hashMerkleRoot.SetNull();
        h.nTime = 1 + i;
        h.nBits = nBits;
        h.nAdjBits = nAdjBits;
        h.nNonce = i;
        h.hashPoW.SetNull();
        h.flags = 0;
        v.push_back(h);
    }
    return v;
}

BOOST_AUTO_TEST_CASE(work_ignores_nadjbits)
{
    SelectParams(ChainType::REGTEST);
    // const auto& cons = Params().GetConsensus();

    // Two forks of equal length with same nBits but different nAdjBits
    const uint32_t nbits = Params().GenesisBlock().nBits;
    const uint32_t adj_easy = nbits;        // same
    const uint32_t adj_hard = nbits - 1;    // different compact (harder)

    auto fork_easy = MakeHeaders(5, nbits, adj_easy);
    auto fork_hard = MakeHeaders(5, nbits, adj_hard);

    auto work_easy = CalculateClaimedHeadersWork(fork_easy);
    auto work_hard = CalculateClaimedHeadersWork(fork_hard);

    // Should be identical because chainwork uses nBits only
    BOOST_CHECK_EQUAL(work_easy.GetLow64(), work_hard.GetLow64());
}

BOOST_AUTO_TEST_CASE(longer_chain_has_more_work)
{
    SelectParams(ChainType::REGTEST);
    const uint32_t nbits = Params().GenesisBlock().nBits;
    auto short_chain = MakeHeaders(3, nbits, nbits + 1);
    auto long_chain  = MakeHeaders(4, nbits, nbits - 1);

    auto work_short = CalculateClaimedHeadersWork(short_chain);
    auto work_long  = CalculateClaimedHeadersWork(long_chain);

    BOOST_CHECK(work_long > work_short);
}

BOOST_AUTO_TEST_SUITE_END()
