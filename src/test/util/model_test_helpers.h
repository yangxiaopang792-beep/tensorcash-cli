#ifndef TENSORCASH_TEST_UTIL_MODEL_TEST_HELPERS_H
#define TENSORCASH_TEST_UTIL_MODEL_TEST_HELPERS_H

#include <consensus/model_verification.h>
#include <wallet/rpc/api_model_registration.h>
#include <modeldb.h>

void SetModelConsensusDefaults(Consensus::Params& consensus,
                               const std::string& model_name,
                               const std::string& model_commit);
uint256 RegisterModelForTest(const ModelMetadata& metadata,
                             ModelRegistrationStatus status,
                             int deposit_height,
                             const Consensus::Params& consensus);

#endif // TENSORCASH_TEST_UTIL_MODEL_TEST_HELPERS_H
