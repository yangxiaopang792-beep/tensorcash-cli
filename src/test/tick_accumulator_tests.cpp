// Negative and reorg-related tests for cumulative_tick integrity

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>

struct TensorRegSetup : public TestingSetup { TensorRegSetup() : TestingSetup{ChainType::TENSOR_REG} {} };

BOOST_FIXTURE_TEST_SUITE(tick_accumulator_tests, TensorRegSetup)

// Reject a block whose cumulative_tick != prev.cumulative_tick + pow.tick
BOOST_AUTO_TEST_CASE(reject_on_bad_cumulative_tick)
{
    // Accept a base block
    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool base_new{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &base_new));

    // Create the next block and then break cumulative_tick invariant
    CBlock bad = CreateTensorBlock(m_node);
    // Make cumulative_tick inconsistent (off by +1)
    bad.cumulative_tick += 1;

    // Commitments and PoW remain fine (short-hash independent of cumulative_tick)
    node::RegenerateCommitments(bad, *Assert(m_node.chainman));

    // Capture validation reason
    struct Catcher : public CValidationInterface {
        uint256 h; std::optional<BlockValidationState> st;
        explicit Catcher(const uint256& x): h(x) {}
        void BlockChecked(const CBlock& b, const BlockValidationState& s) override { if (b.GetHash()==h) st=s; }
    } catcher{bad.GetHash()};

    m_node.validation_signals->RegisterValidationInterface(&catcher);
    auto badptr = std::make_shared<const CBlock>(bad);
    bool ignored{false};
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(badptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));
    m_node.validation_signals->UnregisterValidationInterface(&catcher);

    BOOST_REQUIRE(catcher.st.has_value());
    BOOST_CHECK(!catcher.st->IsValid());
    BOOST_CHECK_EQUAL(catcher.st->GetRejectReason(), "bad-cumulative-tick");
}

BOOST_AUTO_TEST_SUITE_END()

