#include <test/util/golden_vector_loader.h>

#include <univalue.h>
#include <util/strencodings.h>
#include <util/fs.h>

#include <fstream>
#include <sstream>

namespace golden_vectors {

static std::string FindVectorFile(const std::string& filename)
{
    // Bitcoin Core's fs:: deletes operator/(path, string).
    // Use PathFromString to convert, then / with path operands.
    fs::path fn = fs::PathFromString(filename);
    fs::path candidates[] = {
        fs::PathFromString("../shared-utils/kyc-prover") / fn,
        fs::PathFromString("shared-utils/kyc-prover") / fn,
        fs::PathFromString("../../shared-utils/kyc-prover") / fn,
        fs::PathFromString("../../../shared-utils/kyc-prover") / fn,
    };

    for (const auto& candidate : candidates) {
        if (fs::exists(candidate)) {
            return fs::PathToString(candidate);
        }
    }
    return fs::PathToString(fs::PathFromString("../shared-utils/kyc-prover") / fn);
}

std::string GetDefaultGoldenVectorsPath()
{
    return FindVectorFile("vectors/golden_vectors.json");
}

std::string GetDefaultHDV1GoldenVectorsPath()
{
    return FindVectorFile("vectors_hd_v1/golden_vectors_hd_v1.json");
}

bool GoldenVectorsAvailable(const std::string& json_path)
{
    std::string path = json_path.empty() ? GetDefaultGoldenVectorsPath() : json_path;
    return fs::exists(fs::PathFromString(path));
}

std::optional<GoldenVector> LoadGoldenVector(
    const std::string& vector_name,
    const std::string& json_path)
{
    auto all_vectors = LoadAllGoldenVectors(json_path);
    for (const auto& vec : all_vectors) {
        if (vec.name == vector_name) {
            return vec;
        }
    }
    return std::nullopt;
}

std::vector<GoldenVector> LoadAllGoldenVectors(const std::string& json_path)
{
    std::string path = json_path.empty() ? GetDefaultGoldenVectorsPath() : json_path;

    // Read file
    std::ifstream file(path);
    if (!file.is_open()) {
        return {}; // Return empty vector if file not found
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json_str = buffer.str();

    // Parse JSON
    UniValue json_array;
    if (!json_array.read(json_str) || !json_array.isArray()) {
        return {}; // Return empty vector on parse error
    }

    std::vector<GoldenVector> vectors;

    for (size_t i = 0; i < json_array.size(); ++i) {
        const UniValue& obj = json_array[i];
        if (!obj.isObject()) continue;

        GoldenVector vec;

        // Load name
        const UniValue& name_val = obj.find_value("name");
        if (!name_val.isNull()) {
            vec.name = name_val.get_str();
        }

        // Load witness (nested object)
        const UniValue& witness_obj = obj.find_value("witness");
        if (witness_obj.isObject()) {
            const UniValue& secret_val = witness_obj.find_value("secret");
            if (!secret_val.isNull()) vec.witness.secret = secret_val.get_str();

            const UniValue& pubkey_hash_val = witness_obj.find_value("pubkey_hash");
            if (!pubkey_hash_val.isNull()) vec.witness.pubkey_hash = pubkey_hash_val.get_str();

            const UniValue& country_val = witness_obj.find_value("country");
            if (!country_val.isNull()) vec.witness.country = country_val.getInt<uint32_t>();

            const UniValue& age_val = witness_obj.find_value("age");
            if (!age_val.isNull()) vec.witness.age = age_val.getInt<uint32_t>();

            const UniValue& merkle_proof_val = witness_obj.find_value("merkle_proof");
            if (merkle_proof_val.isArray()) {
                for (size_t j = 0; j < merkle_proof_val.size(); ++j) {
                    vec.witness.merkle_proof.push_back(merkle_proof_val[j].get_str());
                }
            }

            const UniValue& merkle_index_val = witness_obj.find_value("merkle_index");
            if (!merkle_index_val.isNull()) vec.witness.merkle_index = merkle_index_val.getInt<uint32_t>();

            const UniValue& merkle_leaf_hash_val = witness_obj.find_value("merkle_leaf_hash");
            if (!merkle_leaf_hash_val.isNull()) vec.witness.merkle_leaf_hash = merkle_leaf_hash_val.get_str();

            const UniValue& chain_separator_val = witness_obj.find_value("chain_separator");
            if (!chain_separator_val.isNull()) vec.witness.chain_separator = chain_separator_val.get_str();

            const UniValue& asset_id_val = witness_obj.find_value("asset_id");
            if (!asset_id_val.isNull()) vec.witness.asset_id = asset_id_val.get_str();

            const UniValue& compliance_root_val = witness_obj.find_value("compliance_root");
            if (!compliance_root_val.isNull()) vec.witness.compliance_root = compliance_root_val.get_str();

            const UniValue& tfr_anchor_val = witness_obj.find_value("tfr_anchor");
            if (!tfr_anchor_val.isNull()) vec.witness.tfr_anchor = tfr_anchor_val.get_str();
        }

        // Load proof_custom_hex (custom 192-byte format for C++, may be empty for invalid vectors)
        const UniValue& proof_hex_val = obj.find_value("proof_custom_hex");
        if (!proof_hex_val.isNull() && !proof_hex_val.get_str().empty()) {
            std::string hex = proof_hex_val.get_str();
            if (hex.size() >= 2 && hex[0] == '0' && hex[1] == 'x') {
                hex = hex.substr(2);
            }
            vec.proof_bytes = ParseHex(hex);
        }

        // Load public_inputs_hex
        const UniValue& inputs_hex_val = obj.find_value("public_inputs_hex");
        if (!inputs_hex_val.isNull() && !inputs_hex_val.get_str().empty()) {
            std::string hex = inputs_hex_val.get_str();
            if (hex.size() >= 2 && hex[0] == '0' && hex[1] == 'x') {
                hex = hex.substr(2);
            }
            vec.public_inputs_bytes = ParseHex(hex);
        }

        // Load vk_hex
        const UniValue& vk_hex_val = obj.find_value("vk_hex");
        if (!vk_hex_val.isNull() && !vk_hex_val.get_str().empty()) {
            std::string hex = vk_hex_val.get_str();
            if (hex.size() >= 2 && hex[0] == '0' && hex[1] == 'x') {
                hex = hex.substr(2);
            }
            vec.vk_bytes = ParseHex(hex);
        }

        // Load should_fail flag
        const UniValue& should_fail_val = obj.find_value("should_fail");
        if (!should_fail_val.isNull()) {
            vec.should_fail = should_fail_val.get_bool();
        } else {
            vec.should_fail = false;
        }

        vectors.push_back(vec);
    }

    return vectors;
}

} // namespace golden_vectors
