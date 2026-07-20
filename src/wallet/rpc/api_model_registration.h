#ifndef MODELREG_H
#define MODELREG_H

#include <consensus/params.h>
#include <modeldb.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <uint256.h>

#include <optional>
#include <string>
#include <vector>

static const std::string MODELREG_NAME_TAG{"MREG_NAME"};
static const std::string MODELREG_COMMIT_TAG{"MREG_COMMIT"};
static const std::string MODELREG_DIFFICULTY_TAG{"MREG_DIFF"};
static const std::string MODELREG_CID_TAG{"MREG_CID"};
static const std::string MODELREG_OPTIONAL_TAG{"MREG_OPT"};
static const std::string MODELREG_DEPOSIT_TAG{"MREG_DEPOSIT"};
static const std::string MODELREG_OWNER_TAG{"MREG_OWNER"};
static const std::string MODELREG_VERDICT_SUCCESS_TAG{"MREG_VERDICT_OK"};
static const std::string MODELREG_VERDICT_FAIL_TAG{"MREG_VERDICT_FAIL"};
static const std::string MODELREG_CHALLENGE_TAG{"MREG_CHALLENGE"};
static const std::string MODELREG_CHALLENGE_COMMIT_TAG{"MREG_CHALLENGE_COMMIT"};

static constexpr unsigned int MODEL_VERIFICATION_BLOCK_COUNT{100};
static constexpr unsigned int SUCCESSFUL_COMMITS_COUNT{50};
static constexpr unsigned int CHALLENGE_VERIFICATION_BLOCK_COUNT{Consensus::CHALLENGE_VERIFICATION_BLOCK_COUNT};
static constexpr unsigned int CHALLENGE_COMMIT_THRESHOLD{50};

struct ModelDepositPayload {
    uint256 model_hash;
    ModelMetadata metadata;
    std::vector<unsigned char> owner_pubkey;
    uint160 owner_key_hash{};
    CAmount deposit_amount{0};
    uint32_t deposit_vout{0};
};

struct ModelCommitPayload {
    bool success{false};
    uint256 model_hash{uint256::ZERO};
    ModelMetadata metadata;
    uint32_t failure_reason{0};
};

struct ModelChallengePayload {
    uint256 block_hash{uint256::ZERO};
    uint32_t deposit_vout{std::numeric_limits<uint32_t>::max()};
};

struct ModelChallengeCommitPayload {
    uint256 model_hash{uint256::ZERO};
};

uint256 HashSHA256(const std::string& model_name, const std::string& model_commit);
uint256 HashSHA256(const ModelMetadata& metadata);

bool ParseModelDepositTx(const CTransaction& tx, ModelDepositPayload& payload, const Consensus::Params& params);
bool ParseModelCommitTx(const CTransaction& tx, ModelCommitPayload& payload);
bool ParseModelChallengeTx(const CTransaction& tx, ModelChallengePayload& payload, const Consensus::Params& params);
bool ParseModelChallengeCommitTx(const CTransaction& tx, ModelChallengeCommitPayload& payload);

bool IsModelDepositTx(const CTransaction& tx, const Consensus::Params& params);
bool IsModelCommitTx(const CTransaction& tx);
bool IsModelChallengeTx(const CTransaction& tx);
bool IsModelChallengeCommitTx(const CTransaction& tx);

std::vector<CScript> CreateModelDepositScripts(const ModelMetadata& metadata, const CPubKey& owner_pubkey);
std::vector<CScript> CreateModelCommitScriptsSuccess(const ModelMetadata& metadata);
CScript CreateModelCommitFailureScript(const uint256& model_hash, uint32_t reason_code);
CScript CreateModelBurnScriptPubKey();
bool IsModelBurnScriptPubKey(const CScript& script);
CScript CreateModelBurnRedeemScriptSig();
CScript CreateModelChallengeScript(const uint256& block_hash);
std::vector<CScript> CreateModelChallengeCommitScript(const uint256& model_hash);

std::vector<CScript> CreateModelRegistrationScript(const std::string& repo,
                                                   const std::string& commit,
                                                   int64_t difficulty_multiplier,
                                                   const std::string& CID = "",
                                                   const std::string& additional_field = "");

#endif
