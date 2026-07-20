// Tests for SPV hysteresis policy math (margin and gating semantics).

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>

#include <cstdint>

static inline arith_uint256 Margin(uint64_t E, int D)
{
    uint64_t base = E / 2;
    return arith_uint256(base) + arith_uint256((uint64_t)(D < 0 ? 0 : D)) * arith_uint256(E);
}

static inline arith_uint256 CumulativeTickFloor(int height, uint64_t tick_per_block, uint32_t slack_days)
{
    static constexpr int64_t SECONDS_PER_DAY{24 * 60 * 60};
    static constexpr int64_t BLOCK_SECONDS{9 * 60};
    if (tick_per_block == 0 || height <= 0) return arith_uint256{};

    const uint64_t slack_seconds{uint64_t{slack_days} * SECONDS_PER_DAY};
    const uint64_t slack_blocks{(slack_seconds + BLOCK_SECONDS - 1) / BLOCK_SECONDS};
    const uint64_t candidate_height{static_cast<uint64_t>(height)};
    if (candidate_height <= slack_blocks) return arith_uint256{};

    return arith_uint256(candidate_height - slack_blocks) * arith_uint256(tick_per_block);
}

BOOST_AUTO_TEST_SUITE(spv_hysteresis_tests)

BOOST_AUTO_TEST_CASE(margin_increases_with_reorg_depth)
{
    uint64_t E = 1000;
    arith_uint256 m0 = Margin(E, 0);
    arith_uint256 m1 = Margin(E, 1);
    arith_uint256 m2 = Margin(E, 2);
    BOOST_CHECK(m1 > m0);
    BOOST_CHECK(m2 > m1);
}

BOOST_AUTO_TEST_CASE(gating_simple)
{
    uint64_t E = 1000;
    int D = 3;
    arith_uint256 margin = Margin(E, D);

    arith_uint256 best = arith_uint256(100000);
    // Candidate below margin -> fail
    arith_uint256 cand1 = best + margin - arith_uint256(1);
    BOOST_CHECK(!(cand1 >= best + margin));
    // Candidate exactly at margin -> pass
    arith_uint256 cand2 = best + margin;
    BOOST_CHECK(cand2 >= best + margin);
    // Candidate above margin -> pass
    arith_uint256 cand3 = best + margin + arith_uint256(5000);
    BOOST_CHECK(cand3 >= best + margin);
}

BOOST_AUTO_TEST_CASE(cumulative_tick_floor_uses_height_with_block_slack)
{
    const uint64_t tick_per_block{40000 * 9 * 60};
    const uint32_t slack_days{2};
    const uint64_t slack_blocks{320};

    BOOST_CHECK_EQUAL(CumulativeTickFloor(slack_blocks, tick_per_block, slack_days).ToString(),
                      arith_uint256{}.ToString());

    const arith_uint256 expected{arith_uint256(10) * arith_uint256(tick_per_block)};
    BOOST_CHECK_EQUAL(CumulativeTickFloor(slack_blocks + 10,
                                          tick_per_block,
                                          slack_days).ToString(),
                      expected.ToString());
}

BOOST_AUTO_TEST_SUITE_END()
