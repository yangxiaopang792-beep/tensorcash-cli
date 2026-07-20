#include <test/util/model_test_helpers.h>

#include <consensus/model_verification.h>
#include <wallet/rpc/api_model_registration.h>
#include <modeldb.h>
#include <consensus/params.h>

#include <cassert>

void SetModelConsensusDefaults(Consensus::Params& consensus,
                               const std::string& model_name,
                               const std::string& model_commit)
{
    consensus.DefaultModelName = model_name;
    consensus.DefaultModelCommit = model_commit;
}

uint256 RegisterModelForTest(const ModelMetadata& metadata,
                             ModelRegistrationStatus status,
                             int deposit_height,
                             const Consensus::Params& consensus)
{
    assert(g_modeldb);
    ModelRecord record;
    record.metadata = metadata;
    record.status = status;
    record.deposit_block_height = deposit_height;
    record.commit_block_height = 0;
    record.burn_block_height = 0;
    record.successful_commit_count = 0;
    record.verification_event_height = 0;
    record.deposit_txid.SetNull();
    record.burn_txid.SetNull();
    record.commit_txid.SetNull();
    const uint256 model_hash = HashSHA256(metadata.model_name, metadata.model_commit);
    g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
    return model_hash;
}
