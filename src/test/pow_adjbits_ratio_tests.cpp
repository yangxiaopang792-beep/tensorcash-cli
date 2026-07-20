// Copyright (c) 2025 TensorCash
// Unit tests for nAdjBits vs nBits ratio enforcement and acceptance edge cases

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <modeldb.h>
#include <validation.h>
#include <arith_uint256.h>
#include <pow.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>

// Local helper for tests: compute model hash as SHA-256 of "name@commit"
static uint256 ModelHash(const std::string& name, const std::string& commit)
{
    std::string input = name + std::string("@") + commit;
    uint256 out;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(input.data()), input.size()).Finalize(out.begin());
    return out;
}

struct TensorRegSetup : public TestingSetup { TensorRegSetup(): TestingSetup{ChainType::TENSOR_REG} {} };

BOOST_FIXTURE_TEST_SUITE(pow_adjbits_ratio_tests, TensorRegSetup)

// RAII helper to temporarily switch chain params and restore on destruction.
struct ScopedChainParams {
    ChainType prev;
    explicit ScopedChainParams(ChainType next) : prev{Params().GetChainType()} { SelectParams(next); }
    ~ScopedChainParams() { SelectParams(prev); }
};

// Helper: mine a block after header mutations (nAdjBits) to satisfy PoW
static void MineWithAdjBits(CBlock& block, const Consensus::Params& params)
{
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetShortHash(), block.nAdjBits, params)) {
        ++block.nNonce;
        // Avoid infinite loop in pathological cases
        BOOST_REQUIRE(block.nNonce != 0);
    }
}

BOOST_AUTO_TEST_CASE(ratio_reject_when_adjbits_not_hard_enough)
{
    // Using TensorReg fixture
    const auto& params = Params().GetConsensus();

    // Create a valid base block and change it to a custom model with difficulty 2x
    CBlock block = CreateTensorBlock(m_node);

    BOOST_REQUIRE(g_modeldb);
    const uint64_t norm = Params().GetConsensus().ModelDifficultyNormalizer;
    ModelRecord rec2;
    rec2.metadata.model_name = "ratio-2x";
    rec2.metadata.model_commit = "v1";
    rec2.metadata.difficulty = static_cast<int64_t>(2 * norm);
    rec2.status = ModelRegistrationStatus::Registered;
    const uint256 model_hash = ModelHash(rec2.metadata.model_name, rec2.metadata.model_commit);
    if (!g_modeldb->Exists(model_hash)) {
        BOOST_REQUIRE(g_modeldb->WriteModel(model_hash, rec2));
    }
    block.pow.model_identifier = rec2.metadata.model_name + "@" + rec2.metadata.model_commit;
    block.hashPoW = block.pow.GetMerkleRoot();

    // Make the block invalid by setting nAdjBits equal to nBits (too easy when difficulty > normalizer)
    block.nAdjBits = block.nBits;
    MineWithAdjBits(block, params);

    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};
    // Expect rejection due to bad-adjusted-bits when difficulty > 1
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
}

BOOST_AUTO_TEST_CASE(ratio_accept_at_boundary)
{
    // Using TensorReg fixture
    const auto& params = Params().GetConsensus();

    // Create a base block and use a 2x difficulty model to test the exact boundary
    CBlock block = CreateTensorBlock(m_node);

    const uint64_t norm = Params().GetConsensus().ModelDifficultyNormalizer;
    BOOST_REQUIRE(g_modeldb);
    ModelRecord rec2;
    rec2.metadata.model_name = "ratio-boundary";
    rec2.metadata.model_commit = "v1";
    rec2.metadata.difficulty = static_cast<int64_t>(2 * norm);
    rec2.status = ModelRegistrationStatus::Registered;
    const uint256 model_hash = ModelHash(rec2.metadata.model_name, rec2.metadata.model_commit);
    if (!g_modeldb->Exists(model_hash)) {
        BOOST_REQUIRE(g_modeldb->WriteModel(model_hash, rec2));
    }
    block.pow.model_identifier = rec2.metadata.model_name + "@" + rec2.metadata.model_commit;
    block.hashPoW = block.pow.GetMerkleRoot();
    // Always use Merkle commitment (VDF SPV active from genesis)
    block.hashPoW = block.pow.GetMerkleRoot();

    // Compute base and allowed adjusted target (scaled by normalizer)
    auto base_target = DeriveTarget(block.nBits, params.powLimit);
    BOOST_REQUIRE(base_target);
    arith_uint256 max_adj = *base_target;
    // floor(base * norm / diff) with diff = 2*norm => base/2
    max_adj /= 2;
    block.nAdjBits = max_adj.GetCompact();

    // Remine since nAdjBits changed
    MineWithAdjBits(block, params);

    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};
    // Expect acceptance at boundary
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
}

BOOST_AUTO_TEST_CASE(ratio_accept_with_diff_normalizer)
{
    // Using TensorReg fixture
    const auto& params = Params().GetConsensus();

    // Create a block then point it to a custom model with difficulty 1
    CBlock block = CreateTensorBlock(m_node);

    // Register a 1x difficulty model (difficulty == normalizer) in ModelDB
    BOOST_REQUIRE(g_modeldb);
    const uint64_t norm = Params().GetConsensus().ModelDifficultyNormalizer;
    ModelRecord one;
    one.metadata.model_name = "ratio-test";
    one.metadata.model_commit = "v1";
    one.metadata.difficulty = static_cast<int64_t>(norm);
    one.status = ModelRegistrationStatus::Registered;
    const uint256 one_hash = ModelHash(one.metadata.model_name, one.metadata.model_commit);
    // Ensure it does not exist
    if (!g_modeldb->Exists(one_hash)) {
        BOOST_REQUIRE(g_modeldb->WriteModel(one_hash, one));
    }

    block.pow.model_identifier = one.metadata.model_name + "@" + one.metadata.model_commit;
    block.hashPoW = block.pow.GetMerkleRoot();

    // With difficulty==normalizer (1x), nAdjBits may equal nBits
    block.nAdjBits = block.nBits;
    MineWithAdjBits(block, params);

    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
}

BOOST_AUTO_TEST_SUITE_END()
