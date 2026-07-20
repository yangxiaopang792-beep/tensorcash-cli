// Debug test to find actual block hash at height 100
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <validation.h>
#include <iostream>

BOOST_AUTO_TEST_SUITE(debug_block_100)

BOOST_FIXTURE_TEST_CASE(show_actual_hash_at_100, TestChain100Setup)
{
    using namespace std;

    // TestChain100Setup already mines 100 blocks in its constructor
    // Just check what the actual hash is
    LOCK(::cs_main);
    auto* tip = m_node.chainman->ActiveChain().Tip();

    cout << "\n=== ACTUAL BLOCK VALUES AT HEIGHT 100 (using TestChain100Setup) ===\n";
    cout << "Height: " << tip->nHeight << "\n";
    cout << "Block Hash: " << tip->GetBlockHash().ToString() << "\n";
    cout << "\nThis is the EXACT hash that TestChain100Setup produces!\n";
    cout << "Use this hash in setup_common.cpp line 495:\n";
    cout << "assert(tip_hash_str == \"" << tip->GetBlockHash().ToString() << "\");\n";
    cout << "====================================================================\n\n";

    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()