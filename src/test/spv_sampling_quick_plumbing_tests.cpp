// SPV sampling path: QuickVerifier plumbing and mock override tests

#include <boost/test/unit_test.hpp>

#include <test/util/setup_common.h>
#include <test/util/mining.h>

#include <chainparams.h>
#include <validationapi.h>
#include <validationapi_mock.h>
#include <vdf/VdfGenerate.h>
#include <kernel/genesis_proof.h>
#include <arith_uint256.h>
#include <pow.h>

BOOST_AUTO_TEST_SUITE(spv_sampling_quick_plumbing_tests)

// Minimal RAII to install the production ValidationAPIMock for the scope
struct ScopedProdValidationApiMock {
    std::unique_ptr<IValidationAPI> previous;
    ValidationAPIMock* mock{nullptr};
    ScopedProdValidationApiMock() {
        previous = std::move(g_ValidationApi);
        auto m = std::make_unique<ValidationAPIMock>();
        mock = m.get();
        g_ValidationApi = std::move(m);
    }
    ~ScopedProdValidationApiMock() { g_ValidationApi = std::move(previous); }
};

// Use Bitcoin RegTest to avoid model-registry enforcement during chain init.
struct RegNetSamplingSetup : public RegTestingSetup {
    RegNetSamplingSetup() : RegTestingSetup{} {}
};

// Local minimal VDF gate rejects on mismatch without touching validation state
BOOST_FIXTURE_TEST_CASE(local_quickverify_rejects_on_vdf_mismatch, RegNetSamplingSetup)
{
    // Ensure no external API is installed
    g_ValidationApi.reset();

    // Create a valid Tensor block with a real VDF proof (small tick)
    CBlock good = CreateTensorBlock(m_node);
    // Manually attach a valid VDF proof (regtest does not auto-produce VDF)
    good.pow.tick = 100;
    good.pow.vdf = vdf::GenerateProofForTesting(good.hashPrevBlock, good.pow.tick, 1024);
    {
        const CBlockIndex* tip = Assert(m_node.chainman)->ActiveChain().Tip();
        const int next_height = tip ? tip->nHeight + 1 : 0;
        const bool expect_merkle = Params().GetConsensus().IsVdfSpvActive(next_height);
        good.hashPoW = good.pow.GetCommitment(expect_merkle);
    }
    
    // Tamper VDF inputs: change tick without recomputing the VDF; QuickVerifier must fail
    CBlock bad = good;
    bad.pow.tick += 1; // invalidate VDF consistency
    auto bad_ptr = std::make_shared<const CBlock>(bad);

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewSampledBlock(bad_ptr));
}

// Production ValidationAPIMock can deterministically override sampling quick gating
// NOTE: With VDF enabled from genesis, we can only test mock rejection of valid blocks.
// We cannot test mock acceptance of invalid VDF because ContextualCheckBlock performs
// non-mockable VDF verification when IsVdfVdfVerifyActive is true.
BOOST_FIXTURE_TEST_CASE(mock_overrides_quickverify, RegNetSamplingSetup)
{
    ScopedProdValidationApiMock scoped_mock;

    // Test 1: Mock forces rejection of a completely valid block
    scoped_mock.mock->SetDefaultResponse(ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_Fail_Smell_Fail);

    // Create a completely valid block with VDF
    CBlock valid = CreateTensorBlock(m_node);
    auto valid_ptr = std::make_shared<const CBlock>(valid);

    // Mock forces rejection despite valid VDF in quick check
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewSampledBlock(valid_ptr));

    // Test 2: Mock accepts a valid block (control test)
    scoped_mock.mock->SetDefaultResponse(ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);

    // Create another valid block
    CBlock valid2 = CreateTensorBlock(m_node);
    auto valid2_ptr = std::make_shared<const CBlock>(valid2);

    // Mock allows acceptance of valid block
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewSampledBlock(valid2_ptr));
}

BOOST_AUTO_TEST_SUITE_END()
