#ifndef BITCOIN_CONSENSUS_MODEL_VERIFICATION_H
#define BITCOIN_CONSENSUS_MODEL_VERIFICATION_H

#include <modeldb.h>
#include <uint256.h>

#include <string>

namespace model_verification {

enum : uint32_t {
    VERIFICATION_OK = 0,
    VERIFICATION_ERR_EMPTY_NAME = 1,
    VERIFICATION_ERR_EMPTY_COMMIT = 2,
    VERIFICATION_ERR_NONPOSITIVE_DIFFICULTY = 3,
    VERIFICATION_ERR_METADATA_TOO_LARGE = 4,
    VERIFICATION_ERR_EXTERNAL_REJECT = 5,
    VERIFICATION_ERR_INSUFFICIENT_COMMITS = 6,
};

struct VerificationResult {
    bool passed{false};
    uint32_t reason_code{VERIFICATION_OK};
    std::string details;
};

VerificationResult VerifyModel(const uint256& model_hash, const ModelMetadata& metadata);

} // namespace model_verification

#endif // BITCOIN_CONSENSUS_MODEL_VERIFICATION_H
