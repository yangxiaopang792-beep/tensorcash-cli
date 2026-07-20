#include <consensus/model_verification.h>

#include <node/model_validation_shims.h>

#include <algorithm>

namespace model_verification {
namespace {
constexpr size_t MAX_NAME_BYTES = 80;
constexpr size_t MAX_COMMIT_BYTES = 80;
constexpr size_t MAX_CID_BYTES = 80; // generous IPFS length allowance
constexpr size_t MAX_EXTRA_BYTES = 80;

bool HasPrintableAscii(const std::string& value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch == '\n' || (ch >= 32 && ch <= 126);
    });
}
} // namespace

VerificationResult VerifyModel(const uint256& model_hash, const ModelMetadata& metadata)
{
    VerificationResult result{true, VERIFICATION_OK, {}};

    if (metadata.model_name.empty() || metadata.model_name.size() > MAX_NAME_BYTES) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_EMPTY_NAME;
        result.details = metadata.model_name.empty() ? "model_name is empty" : "model_name exceeds limit";
        return result;
    }
    if (!HasPrintableAscii(metadata.model_name)) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_METADATA_TOO_LARGE;
        result.details = "model_name contains non-printable characters";
        return result;
    }

    if (metadata.model_commit.empty() || metadata.model_commit.size() > MAX_COMMIT_BYTES) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_EMPTY_COMMIT;
        result.details = metadata.model_commit.empty() ? "model_commit is empty" : "model_commit exceeds limit";
        return result;
    }
    if (!HasPrintableAscii(metadata.model_commit)) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_METADATA_TOO_LARGE;
        result.details = "model_commit contains non-printable characters";
        return result;
    }

    if (metadata.difficulty <= 0) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_NONPOSITIVE_DIFFICULTY;
        result.details = "difficulty must be positive";
        return result;
    }

    if (metadata.cid.size() > MAX_CID_BYTES || metadata.extra.size() > MAX_EXTRA_BYTES) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_METADATA_TOO_LARGE;
        result.details = "metadata fields exceed size limits";
        return result;
    }

    if (!HasPrintableAscii(metadata.cid) || !HasPrintableAscii(metadata.extra)) {
        result.passed = false;
        result.reason_code = VERIFICATION_ERR_METADATA_TOO_LARGE;
        result.details = "metadata fields contain non-printable characters";
        return result;
    }

    return result;
}

} // namespace model_verification
