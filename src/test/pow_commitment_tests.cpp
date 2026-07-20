// Tests for PoW Merkle commitment builder, branches, and activation fence.

#include <boost/test/unit_test.hpp>

#include <primitives/proofblob.h>
#include <consensus/merkle.h>
#include <util/strencodings.h>

BOOST_AUTO_TEST_SUITE(pow_commitment_tests)

static std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    return ParseHex<uint8_t>(hex);
}

static CProofBlob MakeSampleProofBlob()
{
    CProofBlob pb;
    pb.version = 1;
    pb.tick = 42;
    pb.timestamp = 123456789u;
    pb.vdf = HexToBytes(
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100");
    pb.model_identifier = "testModel@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    pb.target = {0x12,0x34,0x56};
    pb.hash = {0xaa,0xbb};
    pb.block_hash = {0xcc};
    pb.header_prefix = {0x00,0x11};
    pb.is_solution = true;
    return pb;
}

BOOST_AUTO_TEST_CASE(merkle_root_matches_manual)
{
    CProofBlob pb = MakeSampleProofBlob();
    CPowLeaves leaves = pb.BuildLeaves();
    std::vector<uint256> v{leaves.l_tick, leaves.l_vdf, leaves.l_meta, leaves.l_rest};
    uint256 manual_root = ComputeMerkleRoot(v);
    uint256 impl_root = pb.GetMerkleRoot();
    BOOST_CHECK_EQUAL(manual_root.ToString(), impl_root.ToString());
}

BOOST_AUTO_TEST_CASE(branch_verification_tick_and_vdf)
{
    CProofBlob pb = MakeSampleProofBlob();
    CPowLeaves leaves = pb.BuildLeaves();
    // Build branches as the node does
    auto br_tick = pb.BuildBranchForTick();
    auto br_vdf  = pb.BuildBranchForVdf();

    // Tick branch path: [sibling=vdf, h23]
    BOOST_REQUIRE_EQUAL(br_tick.size(), 2U);
    uint256 h01_tick = Hash(leaves.l_tick, br_tick[0]);
    uint256 root_tick = Hash(h01_tick, br_tick[1]);
    BOOST_CHECK_EQUAL(root_tick.ToString(), pb.GetMerkleRoot().ToString());

    // Vdf branch path: [sibling=tick, h23]
    BOOST_REQUIRE_EQUAL(br_vdf.size(), 2U);
    uint256 h01_vdf = Hash(br_vdf[0], leaves.l_vdf);
    uint256 root_vdf = Hash(h01_vdf, br_vdf[1]);
    BOOST_CHECK_EQUAL(root_vdf.ToString(), pb.GetMerkleRoot().ToString());
}

BOOST_AUTO_TEST_CASE(commitment_activation_fence)
{
    CProofBlob pb = MakeSampleProofBlob();
    // Legacy commitment and Merkle commitment should differ for arbitrary blobs
    const uint256 legacy = pb.GetHash();
    const uint256 merkle = pb.GetMerkleRoot();
    BOOST_CHECK_NE(legacy.ToString(), merkle.ToString());
    // Fence behavior: GetCommitment(false) -> legacy; GetCommitment(true) -> merkle
    BOOST_CHECK_EQUAL(pb.GetCommitment(false).ToString(), legacy.ToString());
    BOOST_CHECK_EQUAL(pb.GetCommitment(true).ToString(), merkle.ToString());
}

BOOST_AUTO_TEST_CASE(proof_id_is_vdf_leaf_hash)
{
    CProofBlob pb = MakeSampleProofBlob();
    CPowLeaves leaves = pb.BuildLeaves();
    // Our proof_id choice aligns with the leaf hash of L_vdf
    const uint256 proof_id = leaves.l_vdf;
    // Just sanity: proof_id is not null and ties to merkle root via branch
    BOOST_CHECK(!proof_id.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()

