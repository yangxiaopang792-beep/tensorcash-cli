// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Regression tests for the overflow-safe PoW difficulty retarget. On tensor
// mainnet powLimit is ~2^255, so base targets are ~2^247 and the naive
// `target *= nActualTimespan` wraps 256-bit arithmetic before the divide. This
// first manifests at the height-2016 retarget (the first ever — heights 0..2015
// inherit genesis nBits), producing a garbage target ~8000x too hard.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <arith_uint256.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_retarget_overflow_tests, BasicTestingSetup)

// Real on-chain numbers: genesis nBits/time and the height-2015 block time.
// nActualTimespan = 1,887,265 s (~21.8 days vs the 14-day target).
BOOST_AUTO_TEST_CASE(retarget_does_not_overflow_at_first_interval)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TENSOR_MAIN);
    const Consensus::Params& consensus = params->GetConsensus();

    const int64_t genesis_time = 1780329205;
    const int64_t last_time    = 1782216470; // block 2015
    BOOST_CHECK_EQUAL(last_time - genesis_time, 1887265);

    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nBits   = 0x1f5b05b0;
    pindexLast.nTime   = static_cast<uint32_t>(last_time);

    const unsigned int got = CalculateNextWorkRequired(&pindexLast, genesis_time, consensus);

    // Mathematically correct target: the epoch ran ~1.56x slow, so difficulty
    // eases ~1.56x (target grows ~1.56x).
    BOOST_CHECK_EQUAL(got, 0x20008e04U);
    // And must NOT be the wrapped value the buggy multiply produced.
    BOOST_CHECK(got != 0x1e02ca86U);

    // Document the overflow that motivated the fix: the naive 256-bit multiply
    // wraps and yields the bogus ~8000x-harder target.
    arith_uint256 naive;
    naive.SetCompact(0x1f5b05b0);
    naive *= arith_uint256(static_cast<uint64_t>(last_time - genesis_time));
    naive /= arith_uint256(static_cast<uint64_t>(consensus.nPowTargetTimespan));
    BOOST_CHECK_EQUAL(naive.GetCompact(), 0x1e02ca86U);
}

// Mining and validation must agree on the retarget. The corrected target is a
// permitted transition; the old wrapped value is rejected (far below old/4).
BOOST_AUTO_TEST_CASE(permitted_transition_agrees_with_calculation)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::TENSOR_MAIN);
    const Consensus::Params& consensus = params->GetConsensus();

    BOOST_CHECK( PermittedDifficultyTransition(consensus, 2016, 0x1f5b05b0, 0x20008e04));
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, 2016, 0x1f5b05b0, 0x1e02ca86));
}

// The fix is a no-op wherever the naive multiply would not overflow: with a
// Bitcoin-style 2^224 powLimit the corrected path must match the naive one across
// the whole clamp range.
BOOST_AUTO_TEST_CASE(matches_naive_when_no_overflow)
{
    Consensus::Params consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int64_t first = 1000000;
    const int64_t tspan = consensus.nPowTargetTimespan;

    for (int64_t span : {tspan / 4, tspan / 2, tspan, tspan * 2, tspan * 4, tspan * 8}) {
        CBlockIndex last;
        last.nHeight = 2015;
        last.nBits   = 0x1d00ffff;
        last.nTime   = static_cast<uint32_t>(first + span);

        const unsigned int got = CalculateNextWorkRequired(&last, first, consensus);

        // Replicate the legacy computation (safe here: MAIN powLimit ~2^224).
        int64_t a = span;
        if (a < tspan / 4) a = tspan / 4;
        if (a > tspan * 4) a = tspan * 4;
        arith_uint256 expect;
        expect.SetCompact(0x1d00ffff);
        expect *= arith_uint256(static_cast<uint64_t>(a));
        expect /= arith_uint256(static_cast<uint64_t>(tspan));
        const arith_uint256 pl = UintToArith256(consensus.powLimit);
        if (expect > pl) expect = pl;

        BOOST_CHECK_EQUAL(got, expect.GetCompact());
    }
}

BOOST_AUTO_TEST_SUITE_END()
