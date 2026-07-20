// Negative tests for HEADERS_EXT branch verification logic using CProofBlob helpers.

#include <boost/test/unit_test.hpp>

#include <primitives/proofblob.h>

BOOST_AUTO_TEST_SUITE(headers_ext_branch_negative_tests)

static CProofBlob MakeBlob(uint64_t tick_override = 42)
{
    CProofBlob pb;
    pb.version = 1;
    pb.tick = tick_override;
    pb.vdf = {1,2,3,4,5,6,7,8,9}; // arbitrary bytes, not a real VDF
    pb.model_identifier = "model@commit";
    return pb;
}

BOOST_AUTO_TEST_CASE(bad_tick_branch_fails)
{
    CProofBlob pb = MakeBlob(100);
    auto br = pb.BuildBranchForTick();
    auto root = pb.GetMerkleRoot();
    // Mutate tick and recompute leaf
    CProofBlob pb2 = pb; pb2.tick = 200;
    CPowLeaves l2 = pb2.BuildLeaves();
    // Verify the tick branch with mismatched leaf should not reconstruct root
    uint256 h01 = Hash(l2.l_tick, br[0]);
    uint256 root_bad = Hash(h01, br[1]);
    BOOST_CHECK(root_bad != root);
}

BOOST_AUTO_TEST_CASE(bad_vdf_branch_fails)
{
    CProofBlob pb = MakeBlob(100);
    auto br = pb.BuildBranchForVdf();
    auto root = pb.GetMerkleRoot();
    // Mutate vdf and recompute leaf
    CProofBlob pb2 = pb; pb2.vdf.push_back(0xFF);
    CPowLeaves l2 = pb2.BuildLeaves();
    // Verify the vdf branch with mismatched leaf should not reconstruct root
    uint256 h01 = Hash(br[0], l2.l_vdf);
    uint256 root_bad = Hash(h01, br[1]);
    BOOST_CHECK(root_bad != root);
}

BOOST_AUTO_TEST_SUITE_END()

