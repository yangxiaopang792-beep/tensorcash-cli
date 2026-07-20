#include <verification/verification_utils.h>
#include <verification/quick_verifier.h>
#include <util/strencodings.h>

#include <algorithm>
#include <numeric>
#include <cmath>
#include <limits>

namespace verification {

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    // Skip "0x" prefix if present
    size_t start = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        start = 2;
    }

    // Process pairs of hex characters
    for (size_t i = start; i < hex.size(); i += 2) {
        if (i + 1 < hex.size()) {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            bytes.push_back(byte);
        }
    }

    return bytes;
}

CDFResult BuildIdSortedCDF(
    const std::vector<uint32_t>& indices,
    const std::vector<float>& probabilities,
    uint32_t expected_token) {

    CDFResult result;
    result.position = -1;
    result.lower = 0.0f;
    result.upper = 0.0f;

    // Build (index, prob) pairs and filter out zero probabilities
    std::vector<std::pair<uint32_t, float>> id_prob_pairs;
    for (size_t i = 0; i < indices.size(); ++i) {
        if (probabilities[i] > 0) {
            id_prob_pairs.push_back({indices[i], probabilities[i]});
        }
    }

    // Sort by token ID
    std::sort(id_prob_pairs.begin(), id_prob_pairs.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    // Build sorted indices and CDF
    result.sorted_indices.reserve(id_prob_pairs.size());
    result.cdf.reserve(id_prob_pairs.size());

    double cumsum = 0.0;
    for (size_t i = 0; i < id_prob_pairs.size(); ++i) {
        result.sorted_indices.push_back(id_prob_pairs[i].first);
        cumsum += id_prob_pairs[i].second;
        result.cdf.push_back(static_cast<float>(cumsum));

        if (id_prob_pairs[i].first == expected_token) {
            result.position = static_cast<int>(i);
            result.upper = static_cast<float>(cumsum);
            result.lower = (i > 0) ? result.cdf[i - 1] : 0.0f;
        }
    }

    return result;
}

void TryBorderlineAdjustment(
    const std::vector<float>& logits_h,
    const std::vector<float>& logits_l,
    const std::vector<uint32_t>& indices,
    uint32_t expected_token,
    float u_value,
    float& lower_out,
    float& upper_out) {
    QuickVerifier verifier;
    int position = -1;

    float lower_h = 0.0f;
    float upper_h = 0.0f;
    auto probs_h = verifier.ComputeProbabilities(logits_h);
    verifier.ComputeCDF(probs_h, indices, expected_token, lower_h, upper_h, position);

    if (u_value > lower_h && u_value <= upper_h) {
        lower_out = lower_h;
        upper_out = upper_h;
        return;
    }

    auto probs_l = verifier.ComputeProbabilities(logits_l);
    verifier.ComputeCDF(probs_l, indices, expected_token, lower_out, upper_out, position);
}

// Placeholder implementations for test utilities
// These would be fully implemented when integrating with JSON library

TestVector LoadTestVector(const std::string& json_path) {
    TestVector tv;
    // TODO: Implement JSON loading
    // For now, return empty test vector
    return tv;
}

bool SaveTestResults(const std::string& path, const TestVector& results) {
    // TODO: Implement JSON saving
    return true;
}

} // namespace verification
