#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <modeldb.h>
#include <node/context.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <addresstype.h>
#include <coins.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/mock_validation_api.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationapi.h>
#include <wallet/rpc/api_model_registration.h>

using node::RegenerateCommitments;

namespace {

// Mirror sentinel used in validation.cpp for failed challenges.
static const uint256 CHALLENGE_BURN_SENTINEL = [] {
    auto val = uint256::FromHex("00004348414c4c454e47455f4255524e53454e54494e454c0000000000000000");
    Assume(val.has_value());
    return val.value();
}();

struct ScopedMiningModelOverride {
    explicit ScopedMiningModelOverride(const std::string& identifier)
    {
        node::SetMiningModelOverride(identifier);
    }
    ~ScopedMiningModelOverride()
    {
        node::ClearMiningModelOverride();
    }
};

struct ModelChallengeTestSetup : public TestChain100Setup {
    ScopedValidationApiMock validation_mock;

    struct FundingSource {
        CTransactionRef tx;
        uint32_t vout;
        int height;
    };

    std::vector<FundingSource> m_funding_sources;

    void RebuildBlockIndexCandidates() const
    {
        AssertLockHeld(cs_main);
        auto& chainman = *Assert(m_node.chainman);
        Chainstate& chainstate = chainman.ActiveChainstate();
        chainstate.setBlockIndexCandidates.clear();
        for (auto& it : chainman.m_blockman.m_block_index) {
            CBlockIndex* index = &it.second;
            if (!index->IsValid(BLOCK_VALID_TRANSACTIONS)) continue;
            if (!index->HaveNumChainTxs()) continue;
            if (!chainstate.m_chain.Tip()) continue;
            if (chainstate.setBlockIndexCandidates.value_comp()(index, chainstate.m_chain.Tip())) continue;
            chainstate.setBlockIndexCandidates.insert(index);
        }
        if (chainstate.setBlockIndexCandidates.empty() && chainstate.m_chain.Tip()) {
            chainstate.setBlockIndexCandidates.insert(chainstate.m_chain.Tip());
        }
    }

    ModelChallengeTestSetup()
        : TestChain100Setup{ChainType::TENSOR_REG, TestOpts{.extra_args = {"-checkblockindex=0"}}} {
        // Allow quick validation for deterministic block building in tests.
        if (validation_mock.get()) {
            validation_mock->SetDefaultResponse(ValidationReqType::Quick_Smell,
                                                ValidationResponseValue::Quick_OK_Smell_OK);
            validation_mock->SetDefaultResponse(ValidationReqType::Quick,
                                                ValidationResponseValue::Quick_OK_Smell_OK);
        }

        BOOST_TEST_MESSAGE(strprintf("checkblockindex arg=%d", gArgs.GetIntArg("-checkblockindex", -1)));
        BOOST_TEST_MESSAGE(strprintf("ShouldCheckBlockIndex=%d", Assert(m_node.chainman)->ShouldCheckBlockIndex()));

        // Mature enough coinbase outputs for local funding (indexes 0-4).
        mineBlocks(5);

        const auto& consensus = Params().GetConsensus();
        const CTransactionRef& funding_input = m_coinbase_txns.at(0);
        const int funding_input_height = InputHeightForCoin(0);
        const CScript funding_script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

        constexpr size_t FUNDING_OUTPUT_COUNT{5};
        const CAmount funding_value = consensus.ModelChallengeDeposit + COIN;
        const CAmount funding_fee{1000};
        const CAmount input_amount = funding_input->vout[0].nValue;
        const CAmount total_payout = funding_value * FUNDING_OUTPUT_COUNT;
        Assume(input_amount > total_payout + funding_fee);

        std::vector<CTxOut> funding_outputs;
        funding_outputs.reserve(FUNDING_OUTPUT_COUNT + 1);
        for (size_t i = 0; i < FUNDING_OUTPUT_COUNT; ++i) {
            funding_outputs.emplace_back(funding_value, funding_script);
        }
        const CAmount change = input_amount - total_payout - funding_fee;
        if (change > 0) {
            funding_outputs.emplace_back(change, funding_script);
        }

        auto funding_tx_result = CreateValidTransaction(
            {funding_input},
            {COutPoint(funding_input->GetHash(), 0)},
            funding_input_height,
            {coinbaseKey},
            funding_outputs,
            /*feerate=*/std::nullopt,
            /*fee_output=*/std::nullopt);
        CMutableTransaction funding_mtx = std::move(funding_tx_result.first);
        funding_mtx.version = 2;

        CBlock funding_block = CreateAndProcessBlock({funding_mtx}, CScript() << OP_TRUE);

        const int funding_block_height = Assert(m_node.chainman)->ActiveChain().Tip()->nHeight;
        const CTransactionRef funding_ref = MakeTransactionRef(funding_mtx);
        for (uint32_t idx = 0; idx < FUNDING_OUTPUT_COUNT; ++idx) {
            m_funding_sources.push_back(FundingSource{funding_ref, idx, funding_block_height});
        }
    }

    void ResignWithSource(CMutableTransaction& tx,
                          const FundingSource& source,
                          int input_height) const
    {
        FillableSigningProvider keystore;
        keystore.AddKey(coinbaseKey);

        CCoinsView coins_view;
        CCoinsViewCache coins_cache(&coins_view);
        AddCoins(coins_cache, *source.tx, input_height);

        const COutPoint outpoint(source.tx->GetHash(), source.vout);
        auto coin_opt = coins_cache.GetCoin(outpoint);
        Assume(coin_opt.has_value());

        std::map<COutPoint, Coin> input_coins{{outpoint, *coin_opt}};
        std::map<int, bilingual_str> input_errors;
        Assume(SignTransaction(tx, &keystore, input_coins, SIGHASH_ALL, input_errors));
    }

    int InputHeightForCoin(size_t coin_index) const {
        // coinbase at index i was mined in block height i + 1 after genesis
        return static_cast<int>(coin_index) + 1;
    }

    CMutableTransaction MakeChallengeTx(size_t funding_index,
                                        const uint256& challenged_block,
                                        CAmount fee = 10'000) {
        Assert(funding_index < m_funding_sources.size());
        const FundingSource& source = m_funding_sources[funding_index];
        const int input_height = source.height;
        const auto& consensus = Params().GetConsensus();

        const CScript burn_script = CreateModelBurnScriptPubKey();
        const CScript change_script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        const CScript challenge_script = CScript()
                                         << OP_RETURN
                                         << std::vector<unsigned char>(MODELREG_CHALLENGE_TAG.begin(),
                                                                       MODELREG_CHALLENGE_TAG.end())
                                         << std::vector<unsigned char>(challenged_block.begin(),
                                                                       challenged_block.end());

        const CAmount input_amount = source.tx->vout[source.vout].nValue;
        CAmount change = input_amount - consensus.ModelChallengeDeposit - fee;
        if (change < 0) {
            change = 0;
        }

        std::vector<CTxOut> outputs;
        outputs.emplace_back(consensus.ModelChallengeDeposit, burn_script);
        outputs.emplace_back(0, challenge_script);
        if (change > 0) {
            outputs.emplace_back(change, change_script);
        }

        auto [tx, _fee_paid] = CreateValidTransaction(
            {source.tx},
            {COutPoint(source.tx->GetHash(), source.vout)},
            input_height,
            {coinbaseKey},
            outputs,
            /*feerate=*/std::nullopt,
            /*fee_output=*/std::nullopt);
        tx.version = Consensus::MODEL_ACCUSATION_TX_VERSION;
        ResignWithSource(tx, source, input_height);
        return tx;
    }

    CMutableTransaction MakeCommitSuccessTx(size_t funding_index,
                                            const ModelMetadata& metadata,
                                            CAmount desired_fee = 10'000) {
        Assert(funding_index < m_funding_sources.size());
        const FundingSource& source = m_funding_sources[funding_index];
        const int input_height = source.height;

        const CAmount input_amount = source.tx->vout[source.vout].nValue;
        const CAmount fee = std::min(desired_fee, input_amount);
        const CAmount payload_value = input_amount - fee;
        Assume(payload_value >= 0);

        std::vector<CTxOut> outputs;
        const auto scripts = CreateModelCommitScriptsSuccess(metadata);
        for (size_t i = 0; i < scripts.size(); ++i) {
            const CAmount value = i == 0 ? payload_value : 0;
            outputs.emplace_back(value, scripts[i]);
        }

        auto [tx, _fee_paid] = CreateValidTransaction(
            {source.tx},
            {COutPoint(source.tx->GetHash(), source.vout)},
            input_height,
            {coinbaseKey},
            outputs,
            /*feerate=*/std::nullopt,
            /*fee_output=*/std::nullopt);
        tx.version = Consensus::MODEL_REGISTER_COMMIT_TX_VERSION;
        ResignWithSource(tx, source, input_height);
        return tx;
    }

    CMutableTransaction MakeChallengeCommitTx(size_t funding_index,
                                              const uint256& model_hash,
                                              CAmount desired_fee = 10'000) {
        Assert(funding_index < m_funding_sources.size());
        const FundingSource& source = m_funding_sources[funding_index];
        const int input_height = source.height;

        const CAmount input_amount = source.tx->vout[source.vout].nValue;
        const CAmount fee = std::min(desired_fee, input_amount);
        const CAmount change = input_amount - fee;
        Assume(change >= 0);

        std::vector<CTxOut> outputs;
        outputs.emplace_back(0, CreateModelChallengeCommitScript(model_hash).front());
        if (change > 0) {
            const CScript change_script = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
            outputs.emplace_back(change, change_script);
        }

        auto [tx, _fee_paid] = CreateValidTransaction(
            {source.tx},
            {COutPoint(source.tx->GetHash(), source.vout)},
            input_height,
            {coinbaseKey},
            outputs,
            /*feerate=*/std::nullopt,
            /*fee_output=*/std::nullopt);
        tx.version = Consensus::MODEL_CHALLENGE_COMMIT_TX_VERSION;
        ResignWithSource(tx, source, input_height);
        return tx;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(model_challenge_tests, ModelChallengeTestSetup)

BOOST_AUTO_TEST_CASE(mempool_accepts_when_challenge_requires_block_inclusion)
{
    MockValidationAPI* mock = validation_mock.get();
    BOOST_REQUIRE(mock != nullptr);

    const CBlockIndex* tip;
    {
        LOCK(cs_main);
        tip = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    const uint256 target_hash = tip->GetBlockHash();

    mock->ClearAll();
    mock->SetDefaultResponse(ValidationReqType::Challenge,
                             ValidationResponseValue::Challenge_OK);

    CMutableTransaction challenge_tx = MakeChallengeTx(/*coin_index=*/0, target_hash);
    const CTransactionRef challenge_ref = MakeTransactionRef(challenge_tx);

    const MempoolAcceptResult res = [&]() {
        LOCK(cs_main);
        return Assert(m_node.chainman)->ProcessTransaction(challenge_ref);
    }();

    BOOST_CHECK_EQUAL(res.m_result_type, MempoolAcceptResult::ResultType::VALID);
    LOCK(m_node.mempool->cs);
    BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(challenge_ref->GetHash())));
}

BOOST_AUTO_TEST_CASE(mempool_accepts_when_challenge_status_is_fail)
{
    MockValidationAPI* mock = validation_mock.get();
    BOOST_REQUIRE(mock != nullptr);

    const CBlockIndex* tip;
    {
        LOCK(cs_main);
        tip = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    const uint256 target_hash = tip->GetBlockHash();

    mock->ClearAll();
    mock->SetDefaultResponse(ValidationReqType::Challenge,
                             ValidationResponseValue::Challenge_Fail);

    CMutableTransaction challenge_tx = MakeChallengeTx(/*coin_index=*/1, target_hash);
    const CTransactionRef challenge_ref = MakeTransactionRef(challenge_tx);

    const MempoolAcceptResult res = [&]() {
        LOCK(cs_main);
        return Assert(m_node.chainman)->ProcessTransaction(challenge_ref);
    }();

    BOOST_TEST_MESSAGE("challenge_fail reject reason: " + res.m_state.GetRejectReason());

    BOOST_CHECK_EQUAL(res.m_result_type, MempoolAcceptResult::ResultType::VALID);
    LOCK(m_node.mempool->cs);
    BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(challenge_ref->GetHash())));
}

BOOST_AUTO_TEST_CASE(challenge_commits_ban_model_and_cleanup_at_verdict)
{
    MockValidationAPI* mock = validation_mock.get();
    BOOST_REQUIRE(mock != nullptr);

    const CBlockIndex* tip_index;
    {
        LOCK(cs_main);
        tip_index = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    BOOST_REQUIRE(tip_index != nullptr);
    const CBlockIndex* target_index = tip_index->pprev;
    BOOST_REQUIRE(target_index != nullptr);

    CBlock challenged_block;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(challenged_block, *target_index));
    const uint256& target_hash = target_index->GetBlockHash();
    const uint256 model_hash = challenged_block.pow.GetModelHash();

    ModelMetadata alt_metadata;
    alt_metadata.model_name = "challenge_alt_model";
    alt_metadata.model_commit = target_hash.ToString().substr(0, 12);
    const uint64_t norm = Params().GetConsensus().ModelDifficultyNormalizer;
    alt_metadata.difficulty = static_cast<int64_t>(norm == 0 ? 1 : norm);
    const uint256 alt_hash = HashSHA256(alt_metadata);
    ModelRecord alt_record;
    alt_record.metadata = alt_metadata;
    alt_record.status = ModelRegistrationStatus::Registered;
    alt_record.deposit_block_height = Assert(m_node.chainman)->ActiveChain().Height();
    BOOST_REQUIRE(g_modeldb->WriteModel(alt_hash, alt_record, /*overwrite=*/true));
    const std::string alt_identifier = alt_metadata.model_name + "@" + alt_metadata.model_commit;

    // Prepare ModelDB state: ensure record has a deposit entry we can index.
    ModelRecord record;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, record));
    record.status = ModelRegistrationStatus::Registered;
    record.deposit_txid = target_hash;
    record.deposit_vout = 1;
    record.deposit_amount = Params().GetConsensus().ModelChallengeDeposit;
    record.burn_txid.SetNull();
    record.burn_vout = 0;
    record.burn_block_height = 0;
    record.challenge_block_hash.SetNull();
    record.challenge_deposit_txid.SetNull();
    record.challenge_deposit_vout = 0;
    record.challenge_verdict_height = 0;
    record.challenge_commit_count = 0;
    BOOST_REQUIRE(g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true));

    const COutPoint deposit_outpoint(Txid::FromUint256(record.deposit_txid), record.deposit_vout);
    g_modeldb->EraseDepositIndex(deposit_outpoint);
    g_modeldb->EraseBurnIndex(deposit_outpoint);
    BOOST_REQUIRE(g_modeldb->WriteDepositIndex(deposit_outpoint, model_hash));

    // Construct challenge transaction that succeeds (bans the model) once commits are collected.
    mock->SetRequestStatus(target_hash, ValidationReqType::Challenge, ValidationResponseValue::Challenge_OK);
    CMutableTransaction challenge_tx = MakeChallengeTx(/*coin_index=*/1, target_hash);
    const uint256 challenge_txid = challenge_tx.GetHash();
    CreateAndProcessBlock({challenge_tx}, CScript() << OP_TRUE);

    ModelRecord challenged_record;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, challenged_record));
    BOOST_CHECK_EQUAL(challenged_record.challenge_block_hash, target_hash);
    BOOST_CHECK_EQUAL(challenged_record.challenge_deposit_txid, challenge_txid);
    BOOST_CHECK_GT(challenged_record.challenge_verdict_height,
                   Assert(m_node.chainman)->ActiveChain().Height());

    // Preload the commit count so a single commit reaches the threshold.
    challenged_record.challenge_commit_count = CHALLENGE_COMMIT_THRESHOLD - 1;
    BOOST_REQUIRE(g_modeldb->WriteModel(model_hash, challenged_record, /*overwrite=*/true));

    const COutPoint challenge_outpoint(Txid::FromUint256(challenged_record.challenge_deposit_txid),
                                       challenged_record.challenge_deposit_vout);

    // Keep one challenge commit in the mempool so verdict processing can clear it.
    CMutableTransaction mempool_commit = MakeChallengeCommitTx(/*funding_index=*/2, model_hash);
    const CTransactionRef mempool_commit_ref = MakeTransactionRef(mempool_commit);
    {
        LOCK(cs_main);
        const MempoolAcceptResult mempool_res = Assert(m_node.chainman)->ProcessTransaction(mempool_commit_ref);
        BOOST_REQUIRE_EQUAL(mempool_res.m_result_type, MempoolAcceptResult::ResultType::VALID);
    }

    // Mine a commit that pushes the total over the threshold.
    CMutableTransaction threshold_commit = MakeChallengeCommitTx(/*funding_index=*/3, model_hash);
    const CTransactionRef threshold_commit_ref = MakeTransactionRef(threshold_commit);
    {
        LOCK(cs_main);
        const MempoolAcceptResult res = Assert(m_node.chainman)->ProcessTransaction(threshold_commit_ref);
        BOOST_REQUIRE_EQUAL(res.m_result_type, MempoolAcceptResult::ResultType::VALID);
    }
    CreateAndProcessBlock({threshold_commit}, CScript() << OP_TRUE);

    ModelRecord banned_record;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, banned_record));
    BOOST_CHECK(banned_record.status == ModelRegistrationStatus::Banned);
    BOOST_CHECK(banned_record.challenge_commit_count >= CHALLENGE_COMMIT_THRESHOLD);
    BOOST_CHECK(!g_modeldb->LookupModelByDeposit(deposit_outpoint).has_value());
    auto burn_lookup = g_modeldb->LookupModelByBurn(deposit_outpoint);
    BOOST_REQUIRE(burn_lookup.has_value());
    BOOST_CHECK(*burn_lookup == model_hash);

    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(mempool_commit_ref->GetHash())));
    }

    const int current_height = Assert(m_node.chainman)->ActiveChain().Height();
    BOOST_REQUIRE_GT(banned_record.challenge_verdict_height, current_height);
    const int blocks_to_verdict = banned_record.challenge_verdict_height - current_height;
    BOOST_REQUIRE_GT(blocks_to_verdict, 0);
    {
        const ScopedMiningModelOverride override_model(alt_identifier);
        mineBlocks(blocks_to_verdict);
    }

    ModelRecord finalized;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, finalized));
    BOOST_CHECK(finalized.status == ModelRegistrationStatus::Banned);
    BOOST_CHECK(finalized.challenge_block_hash.IsNull());
    BOOST_CHECK(finalized.challenge_deposit_txid.IsNull());
    BOOST_CHECK(!g_modeldb->LookupModelByChallengeDeposit(challenge_outpoint).has_value());
    BOOST_CHECK(!g_modeldb->LookupModelByBurn(challenge_outpoint).has_value());

    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(mempool_commit_ref->GetHash())));
    }
}

BOOST_AUTO_TEST_CASE(connect_block_records_challenge_fail_burn_sentinel)
{
    MockValidationAPI* mock = validation_mock.get();
    BOOST_REQUIRE(mock != nullptr);

    const CBlockIndex* tip_index;
    {
        LOCK(cs_main);
        tip_index = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    BOOST_REQUIRE(tip_index != nullptr);
    const CBlockIndex* target_index = tip_index->pprev;
    BOOST_REQUIRE(target_index != nullptr);
    const uint256 target_hash = target_index->GetBlockHash();

    CBlock challenged_block;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(challenged_block, *target_index));
    const uint256 model_hash = challenged_block.pow.GetModelHash();

    mock->SetRequestStatus(target_hash, ValidationReqType::Challenge, ValidationResponseValue::Challenge_Fail);

    CMutableTransaction challenge_tx = MakeChallengeTx(/*coin_index=*/4, target_hash);
    const uint256 challenge_txid = challenge_tx.GetHash();
    int burn_vout = -1;
    for (size_t i = 0; i < challenge_tx.vout.size(); ++i) {
        if (IsModelBurnScriptPubKey(challenge_tx.vout[i].scriptPubKey)) {
            burn_vout = static_cast<int>(i);
            break;
        }
    }
    BOOST_REQUIRE_GE(burn_vout, 0);
    const COutPoint challenge_burn_outpoint(Txid::FromUint256(challenge_txid),
                                            static_cast<uint32_t>(burn_vout));

    CreateAndProcessBlock({challenge_tx}, CScript() << OP_TRUE);

    ModelRecord challenged_record;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, challenged_record));
    BOOST_CHECK_EQUAL(challenged_record.challenge_deposit_txid, challenge_txid);
    BOOST_REQUIRE_GT(challenged_record.challenge_verdict_height,
                     Assert(m_node.chainman)->ActiveChain().Height());

    const int blocks_to_verdict =
        challenged_record.challenge_verdict_height - Assert(m_node.chainman)->ActiveChain().Height();
    BOOST_REQUIRE_GT(blocks_to_verdict, 0);
    mineBlocks(blocks_to_verdict);

    auto burn_lookup = g_modeldb->LookupModelByBurn(challenge_burn_outpoint);
    BOOST_REQUIRE(burn_lookup.has_value());
    BOOST_CHECK(*burn_lookup == CHALLENGE_BURN_SENTINEL);
    BOOST_CHECK(!g_modeldb->LookupModelByChallengeDeposit(challenge_burn_outpoint).has_value());

    ModelRecord cleared;
    BOOST_REQUIRE(g_modeldb->ReadModel(model_hash, cleared));
    BOOST_CHECK(cleared.challenge_block_hash.IsNull());
    BOOST_CHECK_EQUAL(cleared.challenge_commit_count, 0U);
    BOOST_CHECK(cleared.status == ModelRegistrationStatus::Registered);
}

BOOST_AUTO_TEST_SUITE_END()
