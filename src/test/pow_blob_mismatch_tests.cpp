// Ensure mismatch between powBlob commitment and header hashPoW is rejected

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>

BOOST_FIXTURE_TEST_SUITE(pow_blob_mismatch_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(reject_bad_pow_commitment)
{
    // Accept a base block to establish context
    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool nb{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &nb));

    // Create the next block and then corrupt header's PoW commitment (not the blob)
    CBlock blk = CreateTensorBlock(m_node);
    unsigned char* p = blk.hashPoW.begin();
    p[0] ^= 0x01;

    struct Catcher : public CValidationInterface {
        uint256 h; std::optional<BlockValidationState> st;
        explicit Catcher(const uint256& x): h(x) {}
        void BlockChecked(const CBlock& b, const BlockValidationState& s) override { if (b.GetHash()==h) st=s; }
    } catcher{blk.GetHash()};

    m_node.validation_signals->RegisterValidationInterface(&catcher);
    auto ptr = std::make_shared<const CBlock>(blk);
    bool ignored{false};
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(ptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored));
    m_node.validation_signals->UnregisterValidationInterface(&catcher);

    BOOST_REQUIRE(catcher.st.has_value());
    BOOST_CHECK(!catcher.st->IsValid());
    BOOST_CHECK_EQUAL(catcher.st->GetRejectReason(), "bad-pow-commitment");
}

BOOST_AUTO_TEST_SUITE_END()
