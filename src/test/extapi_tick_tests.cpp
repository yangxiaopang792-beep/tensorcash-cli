// Exercise cumulative_tick update using a simulated ExtAPI solution

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <modeldb.h>
#include <node/miner.h>
#include <coins.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/mock_validation_api.h>
#include <test/util/model_test_helpers.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <validation.h>
#include <vdf/VdfGenerate.h>
#include <script/signingprovider.h>
#include <script/sign.h>
#include <script/solver.h>

using node::RegenerateCommitments;

struct TensorRegSetup : public TestingSetup {
    TensorRegSetup(): TestingSetup{ChainType::TENSOR_REG} {}
};

BOOST_FIXTURE_TEST_SUITE(extapi_tick_tests, TensorRegSetup)

BOOST_AUTO_TEST_CASE(simulated_extapi_solution_sets_cumulative_tick)
{
    // Using TensorReg fixture

    // Mine and accept a base block
    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool base_new{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &base_new));
    BOOST_CHECK(base_new);

    // Build next block template and then simulate ExtAPI filling the PoW blob
    CBlock blk = CreateTensorBlock(m_node);

    // Simulate the miner filling a nonzero tick in the PoW blob and hashing it into hashPoW
    const uint64_t new_tick = 12345;
    blk.pow.tick = new_tick;
    // Generate VDF proof for the new tick value
    blk.pow.vdf = vdf::GenerateProofForTesting(blk.hashPrevBlock, blk.pow.tick, 1024);
    blk.hashPoW = blk.pow.GetCommitment(true);

    // Set cumulative_tick the way ExtAPI does: prev.cumulative_tick + new_tick
    const CBlockIndex* prev_index = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    BOOST_REQUIRE(prev_index);
    CBlock prev_block;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(prev_block, *prev_index));
    const uint64_t expected_cum = prev_block.cumulative_tick + new_tick;
    blk.cumulative_tick = expected_cum;

    // Commitments unaffected by pow blob; keep header fields consistent and mine PoW via nAdjBits if needed
    RegenerateCommitments(blk, *Assert(m_node.chainman));

    auto blkptr = std::make_shared<const CBlock>(blk);
    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blkptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    // Read back from disk and assert cumulative_tick matches expectation
    const CBlockIndex* tip2 = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    BOOST_REQUIRE(tip2);
    CBlock stored;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(stored, *tip2));
    BOOST_CHECK_EQUAL(stored.cumulative_tick, expected_cum);
}

BOOST_AUTO_TEST_CASE(simulated_extapi_multiple_blocks_accumulate_ticks)
{
    // Using TensorReg fixture

    // Accept a starting block
    CBlock b0 = CreateTensorBlock(m_node);
    auto b0ptr = std::make_shared<const CBlock>(b0);
    bool new_b0{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(b0ptr, true, true, &new_b0));
    BOOST_CHECK(new_b0);

    // Prepare a sequence of ticks
    std::vector<uint64_t> ticks{100, 250, 500, 1000};

    uint64_t expected_cum = 0;
    // Get current tip's cumulative for base
    {
        const CBlockIndex* tip = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
        CBlock tipb; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(tipb, *tip));
        expected_cum = tipb.cumulative_tick;
    }

    for (auto t : ticks) {
        // Build next block, set tick and cumulative like ExtAPI would do
        CBlock blk = CreateTensorBlock(m_node);
        blk.pow.tick = t;
        // Generate VDF proof for the new tick value
        blk.pow.vdf = vdf::GenerateProofForTesting(blk.hashPrevBlock, blk.pow.tick, 1024);
        blk.hashPoW = blk.pow.GetCommitment(true);

        const CBlockIndex* prev = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
        CBlock prevb; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(prevb, *prev));
        expected_cum = prevb.cumulative_tick + t;
        blk.cumulative_tick = expected_cum;

        RegenerateCommitments(blk, *Assert(m_node.chainman));
        auto blkptr = std::make_shared<const CBlock>(blk);
        bool new_block{false};
        BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blkptr, true, true, &new_block));
        BOOST_CHECK(new_block);

        const CBlockIndex* tip2 = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
        CBlock stored; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(stored, *tip2));
        BOOST_CHECK_EQUAL(stored.cumulative_tick, expected_cum);
    }
}

BOOST_AUTO_TEST_CASE(challenge_responses_do_not_break_tick_accumulation)
{
    BOOST_REQUIRE(g_modeldb);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct ConsensusDefaultGuard {
        Consensus::Params& params;
        std::string old_name;
        std::string old_commit;
        ~ConsensusDefaultGuard() {
            params.DefaultModelName = old_name;
            params.DefaultModelCommit = old_commit;
        }
    } restore_defaults{consensus, consensus.DefaultModelName, consensus.DefaultModelCommit};
    ScopedGenesisApproval genesis(Params());
    MockValidationAPI& mock_api = *genesis.get();
    mock_api.SetDefaultResponse(ValidationReqType::Challenge, ValidationResponseValue::Challenge_Fail);

    consensus.DefaultModelName = "extapi_challenge_model";
    consensus.DefaultModelCommit = "v1";
    ModelMetadata metadata;
    metadata.model_name = consensus.DefaultModelName;
    metadata.model_commit = consensus.DefaultModelCommit;
    metadata.difficulty = 1;
    RegisterModelForTest(metadata, ModelRegistrationStatus::Registered, 1, consensus);

    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool base_new{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(baseptr, true, true, &base_new));
    BOOST_CHECK(base_new);

    CKey key;
    key.MakeNewKey(true);
    const CScript funding_script = GetScriptForRawPubKey(key.GetPubKey());

    CMutableTransaction synthetic_funding;
    const CAmount challenge_fee = 1000;
    synthetic_funding.version = 2;
    synthetic_funding.vout.emplace_back(consensus.ModelChallengeDeposit + challenge_fee, funding_script);
    const CTransaction funding_prev{synthetic_funding};
    const COutPoint funding_outpoint(funding_prev.GetHash(), 0);

    // Ensure the referenced model is marked registered so the challenge is valid.
    {
        ModelRecord record;
        const uint256 model_hash = base.pow.GetModelHash();
        BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, record));
        record.status = ModelRegistrationStatus::Registered;
        record.challenge_block_hash.SetNull();
        record.challenge_deposit_txid.SetNull();
        record.challenge_verdict_height = 0;
        record.challenge_commit_count = 0;
        BOOST_REQUIRE(g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true));
    }

    {
        LOCK(::cs_main);
        Coin coin;
        coin.out = funding_prev.vout[0];
        coin.nHeight = 1;
        coin.fCoinBase = false;
        Assert(m_node.chainman)->ActiveChainstate().CoinsTip().AddCoin(funding_outpoint, std::move(coin), /*possible_overwrite=*/false);
    }

    CMutableTransaction challenge_tx;
    challenge_tx.version = Consensus::MODEL_ACCUSATION_TX_VERSION;
    challenge_tx.vin.emplace_back(funding_outpoint);
    challenge_tx.vout.emplace_back(consensus.ModelChallengeDeposit, CreateModelBurnScriptPubKey());
    challenge_tx.vout.emplace_back(0, CreateModelChallengeScript(base.GetHash()));

    FillableSigningProvider keystore; keystore.AddKey(key);
    SignatureData sig;
    BOOST_CHECK(SignSignature(keystore, funding_prev, challenge_tx, 0, SIGHASH_ALL, sig));
    UpdateInput(challenge_tx.vin[0], sig);

    mock_api.SetRequestStatus(base.GetHash(), ValidationReqType::Challenge, ValidationResponseValue::Challenge_Fail);
    const MempoolAcceptResult res = m_node.chainman->ProcessTransaction(MakeTransactionRef(challenge_tx));
    BOOST_CHECK_MESSAGE(res.m_result_type != MempoolAcceptResult::ResultType::INVALID,
        std::string("challenge tx rejected: ") + res.m_state.GetRejectReason());
    CBlock block_with_challenge = CreateTensorBlock(m_node);
    const uint256 challenge_txid = challenge_tx.GetHash();
    bool already_in_block = false;
    for (const auto& txref : block_with_challenge.vtx) {
        if (txref->GetHash() == challenge_txid) {
            already_in_block = true;
            break;
        }
    }
    if (!already_in_block) {
        block_with_challenge.vtx.push_back(MakeTransactionRef(challenge_tx));
    }
    node::RegenerateCommitments(block_with_challenge, *Assert(m_node.chainman));
    UpdateTestBlockVdf(block_with_challenge, *Assert(m_node.chainman));
    block_with_challenge.nNonce = 0;
    while (!CheckProofOfWork(block_with_challenge.GetShortHash(), block_with_challenge.nAdjBits, Params().GetConsensus())) {
        ++block_with_challenge.nNonce;
    }
    auto block_with_challenge_ptr = std::make_shared<const CBlock>(block_with_challenge);
    bool block_with_challenge_new{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(block_with_challenge_ptr, true, true, &block_with_challenge_new));
    BOOST_CHECK(block_with_challenge_new);

    CBlock blk = CreateTensorBlock(m_node);
    blk.pow.tick = 321;
    blk.pow.vdf = vdf::GenerateProofForTesting(blk.hashPrevBlock, blk.pow.tick, 1024);
    blk.hashPoW = blk.pow.GetCommitment(true);
    const CBlockIndex* prev = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    CBlock prev_block; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(prev_block, *prev));
    blk.cumulative_tick = prev_block.cumulative_tick + blk.pow.tick;
    RegenerateCommitments(blk, *Assert(m_node.chainman));
    blk.nNonce = 0;
    while (!CheckProofOfWork(blk.GetShortHash(), blk.nAdjBits, Params().GetConsensus())) {
        ++blk.nNonce;
    }
    auto blkptr = std::make_shared<const CBlock>(blk);
    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blkptr, true, true, &new_block));
    BOOST_CHECK(new_block);

    const CBlockIndex* tip = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    CBlock stored; BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(stored, *tip));
    BOOST_CHECK_EQUAL(stored.cumulative_tick, prev_block.cumulative_tick + blk.pow.tick);
}

BOOST_AUTO_TEST_SUITE_END()
