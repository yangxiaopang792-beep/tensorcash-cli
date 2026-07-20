// Tests for EMA tick tracking logic (standalone math)

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(ema_tick_tests)

static double UpdateEma(double ema, double alpha, uint64_t tick, bool init)
{
    if (init) return static_cast<double>(tick);
    return alpha * static_cast<double>(tick) + (1.0 - alpha) * ema;
}

BOOST_AUTO_TEST_CASE(basic_ema_progression)
{
    const double alpha = 0.02;
    double ema = 0.0; bool init = true;
    ema = UpdateEma(ema, alpha, 1000, init); init = false;
    // After first sample, EMA equals first sample
    BOOST_CHECK_CLOSE(ema, 1000.0, 1e-9);
    ema = UpdateEma(ema, alpha, 1500, init);
    // EMA should move towards 1500 but stay below
    BOOST_CHECK(ema > 1000.0 && ema < 1500.0);
    double prev = ema;
    ema = UpdateEma(ema, alpha, 1500, init);
    // With the same sample again, EMA should increase further
    BOOST_CHECK(ema > prev);
}

BOOST_AUTO_TEST_SUITE_END()

