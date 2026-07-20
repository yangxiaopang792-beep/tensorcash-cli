#include <boost/test/unit_test.hpp>

#include <algorithm>

#include <consensus/params.h>
#include <chainparams.h>
#include <key.h>
#include <policy/policy.h>
#include <addresstype.h>
#include <test/util/setup_common.h>
#include <wallet/rpc/api_model_registration.h>

BOOST_FIXTURE_TEST_SUITE(model_registration_sanity_tests, BasicTestingSetup)

static ModelMetadata SampleMetadata()
{
    ModelMetadata metadata;
    metadata.model_name = "tensor/model";
    metadata.model_commit = "commit1";
    metadata.difficulty = 1000000;
    metadata.cid = "QmExample";
    metadata.extra = "unit-test";
    return metadata;
}

static CPubKey MakeTestPubKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key.GetPubKey();
}

BOOST_AUTO_TEST_CASE(parse_deposit_success)
{
    const Consensus::Params& params = Params().GetConsensus();
    const ModelMetadata metadata = SampleMetadata();
    const CPubKey owner_pubkey = MakeTestPubKey();
    const CScript owner_script = GetScriptForDestination(PKHash(owner_pubkey));

    CMutableTransaction mtx;
    mtx.version = Consensus::MODEL_REGISTER_DEPOSIT_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.emplace_back(params.ModelRegistrationDeposit, owner_script);
    for (const auto& sc : CreateModelDepositScripts(metadata, owner_pubkey)) {
        mtx.vout.emplace_back(0, sc);
    }

    ModelDepositPayload payload;
    BOOST_CHECK(ParseModelDepositTx(CTransaction(mtx), payload, params));
    BOOST_CHECK_EQUAL(payload.metadata.model_name, metadata.model_name);
    BOOST_CHECK_EQUAL(payload.metadata.model_commit, metadata.model_commit);
    BOOST_CHECK_EQUAL(payload.metadata.difficulty, metadata.difficulty);
    BOOST_CHECK_EQUAL(payload.deposit_amount, params.ModelRegistrationDeposit);
    BOOST_CHECK(payload.model_hash == HashSHA256(metadata));
}

BOOST_AUTO_TEST_CASE(parse_deposit_missing_owner_fails)
{
    const Consensus::Params& params = Params().GetConsensus();
    const ModelMetadata metadata = SampleMetadata();
    const CPubKey owner_pubkey = MakeTestPubKey();
    const CScript owner_script = GetScriptForDestination(PKHash(owner_pubkey));

    CMutableTransaction mtx;
    mtx.version = Consensus::MODEL_REGISTER_DEPOSIT_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.emplace_back(params.ModelRegistrationDeposit, owner_script);
    auto scripts = CreateModelDepositScripts(metadata, owner_pubkey);
    // drop owner tag
    scripts.erase(std::remove_if(scripts.begin(), scripts.end(), [](const CScript& sc) {
        opcodetype opcode; std::vector<unsigned char> data; CScript::const_iterator pc = sc.begin();
        if (!sc.GetOp(pc, opcode, data) || opcode != OP_RETURN) return false;
        if (!sc.GetOp(pc, opcode, data)) return false;
        std::string tag(data.begin(), data.end());
        return tag == MODELREG_OWNER_TAG;
    }), scripts.end());
    for (const auto& sc : scripts) {
        mtx.vout.emplace_back(0, sc);
    }

    ModelDepositPayload payload;
    BOOST_CHECK(!ParseModelDepositTx(CTransaction(mtx), payload, params));
}

BOOST_AUTO_TEST_CASE(parse_commit_success)
{
    const ModelMetadata metadata = SampleMetadata();
    CMutableTransaction mtx;
    mtx.version = Consensus::MODEL_REGISTER_COMMIT_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.emplace_back(0, CScript());
    mtx.vout.clear();
    for (const auto& sc : CreateModelCommitScriptsSuccess(metadata)) {
        mtx.vout.emplace_back(0, sc);
    }

    ModelCommitPayload payload;
    BOOST_CHECK(ParseModelCommitTx(CTransaction(mtx), payload));
    BOOST_CHECK(payload.success);
    BOOST_CHECK_EQUAL(payload.metadata.model_name, metadata.model_name);
    BOOST_CHECK(payload.model_hash == HashSHA256(metadata));
}

BOOST_AUTO_TEST_CASE(parse_commit_failure)
{
    const ModelMetadata metadata = SampleMetadata();
    const uint256 model_hash = HashSHA256(metadata);
    const uint32_t reason = 42;

    CMutableTransaction mtx;
    mtx.version = Consensus::MODEL_REGISTER_COMMIT_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.emplace_back(0, CreateModelCommitFailureScript(model_hash, reason));
    mtx.vout.emplace_back(1000, CreateModelBurnScriptPubKey());

    ModelCommitPayload payload;
    BOOST_CHECK(ParseModelCommitTx(CTransaction(mtx), payload));
    BOOST_CHECK(!payload.success);
    BOOST_CHECK(payload.model_hash == model_hash);
    BOOST_CHECK_EQUAL(payload.failure_reason, reason);
}

BOOST_AUTO_TEST_SUITE_END()
