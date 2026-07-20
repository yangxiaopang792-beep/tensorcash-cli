// Basic ModelDB persistence tests

#include <boost/test/unit_test.hpp>

#include <modeldb.h>
#include <chainparams.h>
#include <test/util/setup_common.h>
#include <wallet/rpc/api_model_registration.h>
#include <test/util/model_test_helpers.h>
#include <validation.h>
#include <node/context.h>
#include <test/util/mining.h>
#include <iostream>

struct TensorRegSetup : public TestingSetup {
    TensorRegSetup() : TestingSetup{ChainType::TENSOR_REG} {}
};

BOOST_FIXTURE_TEST_SUITE(model_reorg_tests, TensorRegSetup)

BOOST_AUTO_TEST_CASE(modeldb_write_and_erase)
{
    BOOST_REQUIRE(g_modeldb);

    ModelMetadata metadata;
    metadata.model_name = "reorg-test";
    metadata.model_commit = "v1";
    metadata.difficulty = 1000000;

    const uint256 model_hash = HashSHA256(metadata);
    ModelRecord record;
    record.metadata = metadata;
    record.status = ModelRegistrationStatus::PendingDeposit;
    record.deposit_txid.SetNull();
    record.deposit_amount = 0;

    BOOST_CHECK(g_modeldb->WriteModel(model_hash, record, /*overwrite=*/false));

    ModelRecord stored;
    BOOST_CHECK(g_modeldb->ReadModel(model_hash, stored));
    BOOST_CHECK_EQUAL(stored.metadata.model_name, metadata.model_name);

    BOOST_CHECK(g_modeldb->Erase(model_hash));
    BOOST_CHECK(!g_modeldb->Exists(model_hash));
}

BOOST_AUTO_TEST_CASE(model_verification_schedule_persists_across_reorg)
{
    BOOST_REQUIRE(g_modeldb);
    auto& params = const_cast<Consensus::Params&>(Params().GetConsensus());
    const std::string old_default_name = params.DefaultModelName;
    const std::string old_default_commit = params.DefaultModelCommit;

    SetModelConsensusDefaults(params, "sched_model", "sched_commit");

    ModelMetadata metadata;
    metadata.model_name = params.DefaultModelName;
    metadata.model_commit = params.DefaultModelCommit;
    metadata.difficulty = 1;

    const uint256 model_hash = RegisterModelForTest(metadata, ModelRegistrationStatus::Registered, 1, params);

    ModelRecord record;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, record));
    record.verification_event_height = 10;
    g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);

    CModelDB::VerificationValue sched_value;
    g_modeldb->WriteVerificationSchedule(static_cast<uint32_t>(record.verification_event_height), model_hash, sched_value);

    // Mine to height just before the verification event
    for (int i = 0; i < 8; ++i) {
        CBlock block = CreateTensorBlock(m_node);
        ProcessBlock(m_node, std::make_shared<CBlock>(block));
    }

    // Reorg: invalidate last block
    {
        LOCK(cs_main);
        CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
        BOOST_REQUIRE(tip);
        BlockValidationState state;
        BOOST_CHECK(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
        BlockValidationState activate;
        BOOST_CHECK(m_node.chainman->ActiveChainstate().ActivateBestChain(activate, nullptr));
    }

    ModelRecord updated;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, updated));
    BOOST_CHECK_EQUAL(updated.verification_event_height, record.verification_event_height);
    auto sched_lookup = g_modeldb->ReadVerificationSchedule(static_cast<uint32_t>(record.verification_event_height), model_hash);
    BOOST_CHECK(sched_lookup.has_value());

    params.DefaultModelName = old_default_name;
    params.DefaultModelCommit = old_default_commit;
}

BOOST_AUTO_TEST_CASE(model_ban_survives_reorg_and_chainwork_zeroed)
{
    BOOST_REQUIRE(g_modeldb);
    auto& params = const_cast<Consensus::Params&>(Params().GetConsensus());
    const std::string old_default_name = params.DefaultModelName;
    const std::string old_default_commit = params.DefaultModelCommit;

    SetModelConsensusDefaults(params, "ban_model", "ban_commit");

    ModelMetadata metadata;
    metadata.model_name = params.DefaultModelName;
    metadata.model_commit = params.DefaultModelCommit;
    metadata.difficulty = 1;

    const uint256 model_hash = RegisterModelForTest(metadata, ModelRegistrationStatus::Registered, 1, params);

    // Mine a block referencing the model
    CBlock first = CreateTensorBlock(m_node);
    {
        LOCK(cs_main);
        const CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
        BOOST_REQUIRE(tip);
        BOOST_CHECK_EQUAL(first.hashPrevBlock, tip->GetBlockHash());
    }
    auto first_ref = std::make_shared<CBlock>(first);
    ProcessBlock(m_node, first_ref);
    uint256 first_hash = first.GetHash();

    // Mark model as banned and set burn height (simulate challenge success) and zero branch work
    ModelRecord record;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, record));
    record.status = ModelRegistrationStatus::Banned;
    record.burn_block_height = m_node.chainman->ActiveChain().Height();
    g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
    {
        LOCK(cs_main);
        CBlockIndex* first_idx = m_node.chainman->m_blockman.LookupBlockIndex(first_hash);
        BOOST_REQUIRE(first_idx);
        BOOST_REQUIRE(first_idx->pprev);
        first_idx->nChainWork = first_idx->pprev->nChainWork;
    }

    // Reorg: invalidate the last block referencing the banned model
    {
        LOCK(cs_main);
        CBlockIndex* tip = m_node.chainman->ActiveChain().Tip();
        BOOST_REQUIRE(tip);
        BOOST_CHECK_EQUAL(tip->GetBlockHash(), first_hash);
        BlockValidationState state;
        BOOST_CHECK(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
        BlockValidationState activate;
        BOOST_CHECK(m_node.chainman->ActiveChainstate().ActivateBestChain(activate, nullptr));
    }

    {
        LOCK(cs_main);
        CBlockIndex* first_idx = m_node.chainman->m_blockman.LookupBlockIndex(first_hash);
        BOOST_REQUIRE(first_idx);
        BOOST_REQUIRE(first_idx->pprev);
        BOOST_CHECK_EQUAL(first_idx->nChainWork, first_idx->pprev->nChainWork);
    }

    ModelRecord banned_after_reorg;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, banned_after_reorg));
    BOOST_CHECK_EQUAL(banned_after_reorg.status, ModelRegistrationStatus::Banned);
    BOOST_CHECK(banned_after_reorg.burn_block_height != 0);

    params.DefaultModelName = old_default_name;
    params.DefaultModelCommit = old_default_commit;
}

BOOST_AUTO_TEST_SUITE_END()
