// Tests for the VDF verification activation flag in Consensus::Params.

#include <boost/test/unit_test.hpp>

#include <consensus/params.h>

BOOST_AUTO_TEST_SUITE(consensus_vdf_flag_tests)

BOOST_AUTO_TEST_CASE(vdf_verify_activation_flag)
{
    Consensus::Params p{};
    p.vdf_spv_vdfverify_height = 100;
    BOOST_CHECK(!p.IsVdfVdfVerifyActive(0));
    BOOST_CHECK(!p.IsVdfVdfVerifyActive(99));
    BOOST_CHECK(p.IsVdfVdfVerifyActive(100));
    BOOST_CHECK(p.IsVdfVdfVerifyActive(1000));

    p.vdf_spv_vdfverify_height = 0;
    BOOST_CHECK(p.IsVdfVdfVerifyActive(0));
}

BOOST_AUTO_TEST_SUITE_END()

