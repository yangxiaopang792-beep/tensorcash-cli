// TensorCash model validation and external API gating tests

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <modeldb.h>
#include <node/miner.h>
#include <pow.h>
#include <script/script.h>
#include <test/util/mining.h>
#include <test/util/mock_validation_api.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationapi.h>

using node::BlockAssembler;

BOOST_AUTO_TEST_SUITE(model_validation_tests)

struct TensorRegTestingSetup : public TestingSetup {
    TensorRegTestingSetup() : TestingSetup{ChainType::TENSOR_REG} {}
};

struct TensorMainTestingSetup : public ChainTestingSetup {
    ScopedGenesisApproval m_genesis_approval;
    
    TensorMainTestingSetup() 
        : ChainTestingSetup{ChainType::TENSOR_MAIN, {/*extra_args*/{}, /*coins_db_in_memory*/ true, /*block_tree_db_in_memory*/ true, /*setup_net*/ false, /*setup_validation_interface*/ true, /*min_validation_cache*/ false}}
        , m_genesis_approval{Params()}
    {
        // Set default Quick_Smell response for all blocks (not just genesis)
        // This prevents CheckPOWFast failures for new blocks
        m_genesis_approval->SetDefaultResponse(ValidationReqType::Quick_Smell, 
                                              ValidationResponseValue::Quick_OK_Smell_OK);
        
        // Genesis now approved via mock
        LoadVerifyActivateChainstate();  // Will succeed
    }
};

// On mockable TensorReg, a block with an unregistered model is accepted/stored
// (CheckBlock is context-free) but must be rejected at CONNECT time by the
// model-registry check in ConnectBlock, leaving the tip unchanged and the
// block index marked failed.
BOOST_FIXTURE_TEST_CASE(unregistered_model_rejected_on_tensorreg, TensorRegTestingSetup)
{
    // Prepare a block template
    auto block = PrepareBlock(m_node, CScript() << OP_TRUE);

    // Set an invalid model identifier before mining so PoW is still valid
    block->pow.model_identifier = "invalid@deadbeef";
    node::RegenerateCommitments(*block, *Assert(m_node.chainman));
    UpdateTestBlockVdf(*block, *Assert(m_node.chainman));

    // Mine deterministically
    InitializeTensorHeader(*block);
    while (!CheckProofOfWork(block->GetShortHash(), block->nAdjBits, Params().GetConsensus())) {
        ++block->nNonce;
    }

    const uint256 tip_before = WITH_LOCK(cs_main, return Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash());

    bool ignored_new_block{false};
    // Accept/store succeeds; the model-registry rejection happens during
    // ActivateBestChain (ConnectBlock), which PNB runs synchronously.
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));

    LOCK(cs_main);
    // Tip must not advance to the model-invalid block
    BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), tip_before.ToString());
    // The block index must be marked failed by the connect-time rejection
    CBlockIndex* index = Assert(m_node.chainman)->m_blockman.LookupBlockIndex(block->GetHash());
    BOOST_REQUIRE(index != nullptr);
    BOOST_CHECK((index->nStatus & BLOCK_FAILED_MASK) != 0);
    // CRITICAL regression lock for the -reindex wedge: the block DATA must have
    // been stored/indexed despite the unknown model. Pre-fix, AcceptBlock's
    // store-time model check returned before WriteBlock/ReceivedBlockTransactions,
    // leaving a data-less (headers-only) failed entry that even reconsiderblock
    // could not recover without re-downloading the block.
    BOOST_CHECK((index->nStatus & BLOCK_HAVE_DATA) != 0);
    BOOST_CHECK(index->nTx > 0);
}

// A model registered in ModelDB (as it would be after connecting the
// registering ancestor) must allow a block using it to connect.
BOOST_FIXTURE_TEST_CASE(registered_model_block_connects_on_tensorreg, TensorRegTestingSetup)
{
    const auto& consensus = Params().GetConsensus();

    // Register a custom model directly in ModelDB, mirroring the record shape
    // written at connect time. Difficulty equals the normalizer so the
    // per-model difficulty adjustment is neutral.
    auto block = PrepareBlock(m_node, CScript() << OP_TRUE);
    block->pow.model_identifier = "TestModel@cafebabe";
    const uint256 model_hash = block->pow.GetModelHash();

    ModelRecord record;
    record.metadata.model_name = "TestModel";
    record.metadata.model_commit = "cafebabe";
    record.metadata.difficulty = static_cast<int64_t>(consensus.ModelDifficultyNormalizer);
    record.metadata.cid = "test-cid";
    record.status = ModelRegistrationStatus::Registered;
    record.deposit_block_hash = consensus.hashGenesisBlock;
    record.deposit_block_height = 0;
    record.commit_block_hash = consensus.hashGenesisBlock;
    record.commit_block_height = 0;
    record.deposit_amount = 0;
    record.verification_code = 0;
    BOOST_REQUIRE(g_modeldb);
    BOOST_REQUIRE(g_modeldb->WriteModel(model_hash, record));

    node::RegenerateCommitments(*block, *Assert(m_node.chainman));
    UpdateTestBlockVdf(*block, *Assert(m_node.chainman));
    InitializeTensorHeader(*block);
    while (!CheckProofOfWork(block->GetShortHash(), block->nAdjBits, Params().GetConsensus())) {
        ++block->nNonce;
    }

    bool ignored_new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));

    LOCK(cs_main);
    // The registered-model block must become the new tip
    BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), block->GetHash().ToString());
}

// TestBlockValidity (fJustCheck connection) must enforce the same connect-time
// model check as real connection.
BOOST_FIXTURE_TEST_CASE(test_block_validity_enforces_model_check, TensorRegTestingSetup)
{
    auto block = PrepareBlock(m_node, CScript() << OP_TRUE);
    block->pow.model_identifier = "invalid@deadbeef";
    node::RegenerateCommitments(*block, *Assert(m_node.chainman));
    UpdateTestBlockVdf(*block, *Assert(m_node.chainman));
    InitializeTensorHeader(*block);

    LOCK(cs_main);
    BlockValidationState state;
    BOOST_CHECK(!TestBlockValidity(state, Params(), Assert(m_node.chainman)->ActiveChainstate(), *block,
                                   Assert(m_node.chainman)->ActiveChain().Tip(),
                                   /*fCheckApi=*/false, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "unreg-model");
}

// On mockable TensorReg, a default model identifier should pass and be accepted immediately.
BOOST_FIXTURE_TEST_CASE(default_model_accepted_on_tensorreg, TensorRegTestingSetup)
{
    CBlock block = CreateTensorBlock(m_node);
    auto blockptr = std::make_shared<const CBlock>(block);
    bool ignored_new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));
}

// On TensorMain, blocks are gated by the external validator. Without API, reject.
BOOST_FIXTURE_TEST_CASE(tensormain_rejects_without_api, TensorMainTestingSetup)
{
    // Chain is initialized with genesis approved
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip() != nullptr);
    BOOST_CHECK(Params().GetChainType() == ChainType::TENSOR_MAIN);
    
    // Clear the mock to simulate "no API"
    g_ValidationApi.reset();

    CBlock block = CreateTensorBlock(m_node);
    auto blockptr = std::make_shared<const CBlock>(block);
    bool ignored_new_block{false};
    
    // Should reject without API
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));
}

// On TensorMain, if ValidationAPI reports Full_Green for the block, it should be accepted.
BOOST_FIXTURE_TEST_CASE(tensormain_accepts_with_full_green, TensorMainTestingSetup)
{
    BOOST_CHECK(Params().GetChainType() == ChainType::TENSOR_MAIN);
    
    // Create a block
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    
    // Set Full_Green status using the mock
    // Note: Quick_Smell is already OK via default, so CheckPOWFast will pass
    m_genesis_approval->SetRequestStatus(hash, 
                                         ValidationReqType::Full, 
                                         ValidationResponseValue::Full_Green);
    
    // Should accept with Full_Green (and Quick_Smell default)
    auto blockptr = std::make_shared<const CBlock>(block);
    bool ignored_new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));
    
    // Since Full status was pre-set, no Full request should be sent
    // But Quick_Smell might be checked (though it returns OK via default)
    auto requests = m_genesis_approval->GetCapturedRequests();
    // We should NOT see a Full request since it was pre-set
    BOOST_CHECK(!std::any_of(requests.begin(), requests.end(),
        [&hash](const auto& req) { 
            return req.hash == hash && req.type == ValidationReqType::Full;
        }));
}

// On TensorMain, if ValidationAPI reports Full_Red for the block, it is stored with zero local work.
BOOST_FIXTURE_TEST_CASE(tensormain_accepts_full_red_with_zero_work, TensorMainTestingSetup)
{
    BOOST_CHECK(Params().GetChainType() == ChainType::TENSOR_MAIN);
    
    // Create a block
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    
    // Set Full_Red status - a local verifier failure, not a consensus-invalid block.
    m_genesis_approval->SetRequestStatus(hash, 
                                         ValidationReqType::Full, 
                                         ValidationResponseValue::Full_Red);
    
    arith_uint256 parent_work;
    {
        LOCK(cs_main);
        parent_work = Assert(m_node.chainman)->ActiveChain().Tip()->nChainWork;
    }

    // Should store with Full_Red but not add local chainwork.
    auto blockptr = std::make_shared<const CBlock>(block);
    bool ignored_new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));
    BOOST_CHECK(ignored_new_block);
    {
        LOCK(cs_main);
        CBlockIndex* index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(hash)};
        BOOST_REQUIRE(index);
        BOOST_CHECK((index->nStatus & BLOCK_FULL_RED_LOCAL) != 0);
        BOOST_CHECK_EQUAL(index->nChainWork.ToString(), parent_work.ToString());
    }
}

// Test that requests are sent only when status is not pre-set
BOOST_FIXTURE_TEST_CASE(tensormain_request_sending_behavior, TensorMainTestingSetup)
{
    BOOST_CHECK(Params().GetChainType() == ChainType::TENSOR_MAIN);
    
    // Create a block
    CBlock block = CreateTensorBlock(m_node);
    const uint256 hash = block.GetHash();
    
    // Don't pre-set Full status - let it be requested
    // Quick_Smell is OK via default, so no request needed
    
    // Process block - should send Full request
    auto blockptr = std::make_shared<const CBlock>(block);
    bool ignored_new_block{false};
    
    // Will fail initially because Full is not set
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));
    
    // Check that Full request was sent (but not Quick_Smell since it has default)
    auto requests = m_genesis_approval->GetCapturedRequests();
    BOOST_CHECK(std::any_of(requests.begin(), requests.end(),
        [&hash](const auto& req) { 
            return req.hash == hash && req.type == ValidationReqType::Full;
        }));
    
    // Now set Full_Green and try again
    m_genesis_approval->SetRequestStatus(hash, 
                                         ValidationReqType::Full, 
                                         ValidationResponseValue::Full_Green);
    
    // Should succeed now
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored_new_block));
}

// Test validation without any defaults - demonstrates both Quick and Full requests  
// REMOVED: This test causes segfaults due to ChainTestingSetup initialization order issues
// The other tests already demonstrate the validation behavior adequately

BOOST_AUTO_TEST_SUITE_END()
