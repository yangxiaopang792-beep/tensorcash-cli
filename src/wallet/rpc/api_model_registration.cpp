#include <wallet/rpc/api_model_registration.h>

#include <policy/policy.h>
#include <addresstype.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <script/script.h>

#include <algorithm>
#include <cstring>

namespace {

struct ParsedMetadata {
    ModelMetadata metadata;
    bool has_name{false};
    bool has_commit{false};
    bool has_difficulty{false};
};

bool ExtractMetadataFromScripts(const std::vector<CScript>& scripts, ModelMetadata& out)
{
    ParsedMetadata parsed;
    int64_t difficulty_tmp{0};

    for (const auto& script : scripts) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (!script.GetOp(pc, opcode, data)) continue;

        if (tag == MODELREG_NAME_TAG) {
            parsed.metadata.model_name = std::string(data.begin(), data.end());
            parsed.has_name = true;
        } else if (tag == MODELREG_COMMIT_TAG) {
            parsed.metadata.model_commit = std::string(data.begin(), data.end());
            parsed.has_commit = true;
        } else if (tag == MODELREG_DIFFICULTY_TAG) {
            if (data.size() != sizeof(int64_t)) return false;
            std::memcpy(&difficulty_tmp, data.data(), sizeof(int64_t));
            parsed.metadata.difficulty = difficulty_tmp;
            parsed.has_difficulty = true;
        } else if (tag == MODELREG_CID_TAG) {
            parsed.metadata.cid = std::string(data.begin(), data.end());
        } else if (tag == MODELREG_OPTIONAL_TAG) {
            parsed.metadata.extra = std::string(data.begin(), data.end());
        }
    }

    if (!parsed.has_name || !parsed.has_commit || !parsed.has_difficulty) {
        return false;
    }
    out = std::move(parsed.metadata);
    return true;
}

const CScript& BurnRedeemScript()
{
    static const CScript script = CScript() << OP_TRUE;
    return script;
}

bool ExtractOwnerPubKey(const std::vector<CScript>& scripts, std::vector<unsigned char>& pubkey_out)
{
    for (const auto& script : scripts) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (!script.GetOp(pc, opcode, data)) continue;
        if (tag == MODELREG_OWNER_TAG) {
            pubkey_out = data;
            return true;
        }
    }
    return false;
}

bool ExtractModelHashFromDeposit(const std::vector<CScript>& scripts, uint256& hash_out)
{
    for (const auto& script : scripts) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (!script.GetOp(pc, opcode, data)) continue;
        if (tag == MODELREG_DEPOSIT_TAG) {
            if (data.size() != hash_out.size()) {
                return false;
            }
            std::copy(data.begin(), data.end(), hash_out.begin());
            return true;
        }
    }
    return false;
}

bool ExtractFailurePayload(const std::vector<CScript>& scripts, ModelCommitPayload& payload)
{
    for (const auto& script : scripts) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (!script.GetOp(pc, opcode, data)) continue;
        if (tag == MODELREG_VERDICT_FAIL_TAG) {
            if (data.size() < 36) {
                return false;
            }
            std::copy(data.begin(), data.begin() + 32, payload.model_hash.begin());
            uint32_t reason{0};
            std::memcpy(&reason, &data[32], sizeof(uint32_t));
            payload.failure_reason = reason;
            payload.success = false;
            return true;
        }
    }
    return false;
}

} // namespace

uint256 HashSHA256(const std::string& model_name, const std::string& model_commit)
{
    CSHA256 hasher;
    std::string input = model_name + '@' + model_commit;
    uint256 result;
    hasher.Write(reinterpret_cast<const unsigned char*>(input.data()), input.size()).Finalize(result.begin());
    return result;
}

uint256 HashSHA256(const ModelMetadata& metadata)
{
    return HashSHA256(metadata.model_name, metadata.model_commit);
}

CScript CreateModelChallengeScript(const uint256& block_hash)
{
    return CScript() << OP_RETURN
                     << std::vector<unsigned char>(MODELREG_CHALLENGE_TAG.begin(), MODELREG_CHALLENGE_TAG.end())
                     << std::vector<unsigned char>(block_hash.begin(), block_hash.end());
}

std::vector<CScript> CreateModelChallengeCommitScript(const uint256& model_hash)
{
    std::vector<CScript> scripts;
    scripts.emplace_back(CScript() << OP_RETURN
                     << std::vector<unsigned char>(MODELREG_CHALLENGE_COMMIT_TAG.begin(), MODELREG_CHALLENGE_COMMIT_TAG.end())
                     << std::vector<unsigned char>(model_hash.begin(), model_hash.end()));

    return scripts;
}

bool ParseModelDepositTx(const CTransaction& tx, ModelDepositPayload& payload, const Consensus::Params& params)
{
    if (tx.version != static_cast<int32_t>(Consensus::MODEL_REGISTER_DEPOSIT_TX_VERSION)) {
        return false;
    }

    std::vector<CScript> op_returns;
    op_returns.reserve(tx.vout.size());
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.IsUnspendable()) {
            op_returns.push_back(out.scriptPubKey);
        }
    }
    if (op_returns.empty()) return false;

    if (!ExtractMetadataFromScripts(op_returns, payload.metadata)) {
        return false;
    }
    if (!ExtractModelHashFromDeposit(op_returns, payload.model_hash)) {
        return false;
    }
    if (!ExtractOwnerPubKey(op_returns, payload.owner_pubkey)) {
        return false;
    }

    CPubKey owner_pub(payload.owner_pubkey.begin(), payload.owner_pubkey.end());
    if (!owner_pub.IsFullyValid()) {
        return false;
    }

    const uint256 expected_hash = HashSHA256(payload.metadata);
    if (expected_hash != payload.model_hash) {
        return false;
    }

    CAmount deposit_amount{0};
    bool found_deposit_output{false};
    uint32_t deposit_vout{0};
    for (uint32_t idx = 0; idx < tx.vout.size(); ++idx) {
        const auto& out = tx.vout[idx];
        CTxDestination dest;
        if (!ExtractDestination(out.scriptPubKey, dest)) {
            continue;
        }
        const auto* key_hash = std::get_if<PKHash>(&dest);
        if (!key_hash) continue;
        const CKeyID key_id = ToKeyID(*key_hash);

        if (owner_pub.GetID() != key_id) continue;

        if (out.nValue < params.ModelRegistrationDeposit) return false;
        if (found_deposit_output) {
            return false;
        }

        payload.owner_key_hash = key_id;
        deposit_amount = out.nValue;
        deposit_vout = idx;
        found_deposit_output = true;
    }
    if (!found_deposit_output) {
        return false;
    }
    payload.deposit_amount = deposit_amount;
    payload.deposit_vout = deposit_vout;
    return true;
}

bool ParseModelCommitTx(const CTransaction& tx, ModelCommitPayload& payload)
{
    if (tx.version != static_cast<int32_t>(Consensus::MODEL_REGISTER_COMMIT_TX_VERSION)) {
        return false;
    }
    std::vector<CScript> op_returns;
    op_returns.reserve(tx.vout.size());
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.IsUnspendable()) {
            op_returns.push_back(out.scriptPubKey);
        }
    }
    if (op_returns.empty()) {
        return false;
    }

    // Determine verdict type by scanning tags
    bool has_success_tag{false};
    for (const auto& script : op_returns) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (tag == MODELREG_VERDICT_SUCCESS_TAG) {
            has_success_tag = true;
            break;
        }
    }

    if (has_success_tag) {
        if (!ExtractMetadataFromScripts(op_returns, payload.metadata)) {
            return false;
        }
        payload.model_hash = HashSHA256(payload.metadata);
        payload.success = true;
        payload.failure_reason = 0;
        return true;
    }

    // Failure path expects dedicated failure tag payload
    if (!ExtractFailurePayload(op_returns, payload)) {
        return false;
    }
    payload.metadata = ModelMetadata{};
    return true;
}

bool ParseModelChallengeTx(const CTransaction& tx, ModelChallengePayload& payload, const Consensus::Params& params)
{
    if (tx.version != static_cast<int32_t>(Consensus::MODEL_ACCUSATION_TX_VERSION)) {
        return false;
    }

    std::vector<CScript> op_returns;
    op_returns.reserve(tx.vout.size());

    if (tx.vout.empty()) return false;

    // For determinism, the challenge deposit tx is constructed with the deposit
    // output first. Validate and fix the index explicitly instead of scanning.
    const CAmount deposit_amount = params.ModelChallengeDeposit;
    if (tx.vout[0].scriptPubKey.IsUnspendable()) return false;
    if (tx.vout[0].nValue < deposit_amount) return false;
    payload.deposit_vout = 0;
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.IsUnspendable()) {
            op_returns.push_back(out.scriptPubKey);
        }
    }

    bool found_tag{false};
    for (const auto& script : op_returns) {
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (!script.GetOp(pc, opcode, data)) continue;
        if (tag == MODELREG_CHALLENGE_TAG) {
            if (found_tag) {
                return false;
            }
            if (data.size() != payload.block_hash.size()) {
                return false;
            }
            std::copy(data.begin(), data.end(), payload.block_hash.begin());
            found_tag = true;
        }
    }

    if (!found_tag) {
        return false;
    }
    if (payload.deposit_vout == std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    return true;
}

bool IsModelChallengeTx(const CTransaction& tx)
{
    return tx.version == static_cast<int32_t>(Consensus::MODEL_ACCUSATION_TX_VERSION);
}

bool ParseModelChallengeCommitTx(const CTransaction& tx, ModelChallengeCommitPayload& payload)
{
    if (tx.version != static_cast<int32_t>(Consensus::MODEL_CHALLENGE_COMMIT_TX_VERSION)) {
        return false;
    }

    bool found_tag{false};
    for (const auto& out : tx.vout) {
        if (!out.scriptPubKey.IsUnspendable()) {
            continue;
        }
        opcodetype opcode;
        CScript::const_iterator pc = out.scriptPubKey.begin();
        std::vector<unsigned char> data;
        if (!out.scriptPubKey.GetOp(pc, opcode, data) || opcode != OP_RETURN) continue;
        if (!out.scriptPubKey.GetOp(pc, opcode, data)) continue;
        std::string tag(data.begin(), data.end());
        if (!out.scriptPubKey.GetOp(pc, opcode, data)) continue;
        if (tag == MODELREG_CHALLENGE_COMMIT_TAG) {
            if (found_tag) return false;
            if (data.size() != payload.model_hash.size()) return false;
            std::copy(data.begin(), data.end(), payload.model_hash.begin());
            found_tag = true;
        }
    }

    if (!found_tag) return false;
    return true;
}

bool IsModelChallengeCommitTx(const CTransaction& tx)
{
    ModelChallengeCommitPayload payload;
    return ParseModelChallengeCommitTx(tx, payload);
}

bool IsModelDepositTx(const CTransaction& tx, const Consensus::Params& params)
{
    ModelDepositPayload payload;
    return ParseModelDepositTx(tx, payload, params);
}

bool IsModelCommitTx(const CTransaction& tx)
{
    ModelCommitPayload payload;
    return ParseModelCommitTx(tx, payload);
}

std::vector<CScript> CreateModelDepositScripts(const ModelMetadata& metadata, const CPubKey& owner_pubkey)
{
    uint256 model_hash = HashSHA256(metadata);
    std::vector<CScript> scripts;

    uint8_t difficulty_bytes[sizeof(int64_t)];
    std::memcpy(difficulty_bytes, &metadata.difficulty, sizeof(int64_t));

    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_NAME_TAG.begin(), MODELREG_NAME_TAG.end())
                                   << std::vector<unsigned char>(metadata.model_name.begin(), metadata.model_name.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_COMMIT_TAG.begin(), MODELREG_COMMIT_TAG.end())
                                   << std::vector<unsigned char>(metadata.model_commit.begin(), metadata.model_commit.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_DIFFICULTY_TAG.begin(), MODELREG_DIFFICULTY_TAG.end())
                                   << std::vector<unsigned char>(difficulty_bytes, difficulty_bytes + sizeof(int64_t)));
    if (!metadata.cid.empty()) {
        scripts.emplace_back(CScript() << OP_RETURN
                                       << std::vector<unsigned char>(MODELREG_CID_TAG.begin(), MODELREG_CID_TAG.end())
                                       << std::vector<unsigned char>(metadata.cid.begin(), metadata.cid.end()));
    }
    if (!metadata.extra.empty()) {
        scripts.emplace_back(CScript() << OP_RETURN
                                       << std::vector<unsigned char>(MODELREG_OPTIONAL_TAG.begin(), MODELREG_OPTIONAL_TAG.end())
                                       << std::vector<unsigned char>(metadata.extra.begin(), metadata.extra.end()));
    }

    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_DEPOSIT_TAG.begin(), MODELREG_DEPOSIT_TAG.end())
                                   << std::vector<unsigned char>(model_hash.begin(), model_hash.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_OWNER_TAG.begin(), MODELREG_OWNER_TAG.end())
                                   << std::vector<unsigned char>(owner_pubkey.begin(), owner_pubkey.end()));

    return scripts;
}

std::vector<CScript> CreateModelCommitScriptsSuccess(const ModelMetadata& metadata)
{
    uint8_t difficulty_bytes[sizeof(int64_t)];
    std::memcpy(difficulty_bytes, &metadata.difficulty, sizeof(int64_t));

    std::vector<CScript> scripts;
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_NAME_TAG.begin(), MODELREG_NAME_TAG.end())
                                   << std::vector<unsigned char>(metadata.model_name.begin(), metadata.model_name.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_COMMIT_TAG.begin(), MODELREG_COMMIT_TAG.end())
                                   << std::vector<unsigned char>(metadata.model_commit.begin(), metadata.model_commit.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_DIFFICULTY_TAG.begin(), MODELREG_DIFFICULTY_TAG.end())
                                   << std::vector<unsigned char>(difficulty_bytes, difficulty_bytes + sizeof(int64_t)));
    if (!metadata.cid.empty()) {
        scripts.emplace_back(CScript() << OP_RETURN
                                       << std::vector<unsigned char>(MODELREG_CID_TAG.begin(), MODELREG_CID_TAG.end())
                                       << std::vector<unsigned char>(metadata.cid.begin(), metadata.cid.end()));
    }
    if (!metadata.extra.empty()) {
        scripts.emplace_back(CScript() << OP_RETURN
                                       << std::vector<unsigned char>(MODELREG_OPTIONAL_TAG.begin(), MODELREG_OPTIONAL_TAG.end())
                                       << std::vector<unsigned char>(metadata.extra.begin(), metadata.extra.end()));
    }
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_VERDICT_SUCCESS_TAG.begin(), MODELREG_VERDICT_SUCCESS_TAG.end())
                                   << std::vector<unsigned char>());
    return scripts;
}

CScript CreateModelCommitFailureScript(const uint256& model_hash, uint32_t reason_code)
{
    std::vector<unsigned char> payload(model_hash.size() + sizeof(uint32_t));
    std::copy(model_hash.begin(), model_hash.end(), payload.begin());
    std::memcpy(payload.data() + model_hash.size(), &reason_code, sizeof(uint32_t));
    return CScript() << OP_RETURN
                     << std::vector<unsigned char>(MODELREG_VERDICT_FAIL_TAG.begin(), MODELREG_VERDICT_FAIL_TAG.end())
                     << payload;
}

CScript CreateModelBurnScriptPubKey()
{
    const CScript& redeem = BurnRedeemScript();
    const uint160 script_hash = Hash160(std::vector<unsigned char>(redeem.begin(), redeem.end()));
    return CScript() << OP_HASH160 << ToByteVector(script_hash) << OP_EQUAL;
}

bool IsModelBurnScriptPubKey(const CScript& script)
{
    static const CScript expected = CreateModelBurnScriptPubKey();
    return script == expected;
}

CScript CreateModelBurnRedeemScriptSig()
{
    return CScript() << ToByteVector(BurnRedeemScript());
}

std::vector<CScript> CreateModelRegistrationScript(const std::string& repo,
                                                   const std::string& commit,
                                                   int64_t difficulty_multiplier,
                                                   const std::string& CID,
                                                   const std::string& additional_field)
{
    ModelMetadata metadata;
    metadata.model_name = repo;
    metadata.model_commit = commit;
    metadata.difficulty = difficulty_multiplier;
    metadata.cid = CID;
    metadata.extra = additional_field;

    uint8_t difficulty_bytes[sizeof(int64_t)];
    std::memcpy(difficulty_bytes, &difficulty_multiplier, sizeof(int64_t));

    std::vector<CScript> scripts;
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_NAME_TAG.begin(), MODELREG_NAME_TAG.end())
                                   << std::vector<unsigned char>(repo.begin(), repo.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_COMMIT_TAG.begin(), MODELREG_COMMIT_TAG.end())
                                   << std::vector<unsigned char>(commit.begin(), commit.end()));
    scripts.emplace_back(CScript() << OP_RETURN
                                   << std::vector<unsigned char>(MODELREG_DIFFICULTY_TAG.begin(), MODELREG_DIFFICULTY_TAG.end())
                                   << std::vector<unsigned char>(difficulty_bytes, difficulty_bytes + sizeof(int64_t)));
    if (!CID.empty()) {
        scripts.emplace_back(CScript() << OP_RETURN
                                       << std::vector<unsigned char>(MODELREG_CID_TAG.begin(), MODELREG_CID_TAG.end())
                                       << std::vector<unsigned char>(CID.begin(), CID.end()));
    }
    if (!additional_field.empty()) {
        scripts.emplace_back(CScript() << OP_RETURN
                                       << std::vector<unsigned char>(MODELREG_OPTIONAL_TAG.begin(), MODELREG_OPTIONAL_TAG.end())
                                       << std::vector<unsigned char>(additional_field.begin(), additional_field.end()));
    }
    return scripts;
}
