#ifndef BITCOIN_VERIFICATION_UTILS_H
#define BITCOIN_VERIFICATION_UTILS_H

#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include <map>

namespace verification {

// Hex string to bytes conversion
std::vector<uint8_t> HexToBytes(const std::string& hex);

// Build ID-sorted CDFs for verification
struct CDFResult {
    int position;
    float lower;
    float upper;
    std::vector<float> cdf;
    std::vector<uint32_t> sorted_indices;
};

CDFResult BuildIdSortedCDF(
    const std::vector<uint32_t>& indices,
    const std::vector<float>& probabilities,
    uint32_t expected_token
);

// Conditional sampling for borderline top-p cases.
// The adjusted logits are expected to already be in original token order.
void TryBorderlineAdjustment(
    const std::vector<float>& logits_h,
    const std::vector<float>& logits_l,
    const std::vector<uint32_t>& indices,
    uint32_t expected_token,
    float u_value,
    float& lower_out,
    float& upper_out
);

// Sorting utilities
template<typename T>
std::vector<size_t> ArgSort(const std::vector<T>& values, bool descending = false) {
    std::vector<size_t> indices(values.size());
    for (size_t i = 0; i < indices.size(); ++i) {
        indices[i] = i;
    }

    if (descending) {
        std::stable_sort(indices.begin(), indices.end(),
            [&values](size_t i1, size_t i2) {
                return values[i1] > values[i2];
            });
    } else {
        std::stable_sort(indices.begin(), indices.end(),
            [&values](size_t i1, size_t i2) {
                return values[i1] < values[i2];
            });
    }

    return indices;
}

// Get k-th value for top-k filtering
template<typename T>
T KthValue(std::vector<T> values, size_t k) {
    if (k >= values.size()) {
        return values.back();
    }
    std::nth_element(values.begin(), values.begin() + k, values.end());
    return values[k];
}

// Check if element is in container
template<typename T>
bool IsIn(const T& element, const std::vector<T>& container) {
    return std::find(container.begin(), container.end(), element) != container.end();
}

// Deduplicate keep max (for logits)
template<typename T>
void DedupeKeepMax(
    const std::vector<T>& values,
    const std::vector<uint32_t>& indices,
    std::vector<T>& out_values,
    std::vector<uint32_t>& out_indices
) {
    std::map<uint32_t, T> tok_to_max;

    for (size_t i = 0; i < indices.size(); ++i) {
        uint32_t tok = indices[i];
        T val = values[i];

        auto it = tok_to_max.find(tok);
        if (it == tok_to_max.end() || val > it->second) {
            tok_to_max[tok] = val;
        }
    }

    out_indices.clear();
    out_values.clear();
    out_indices.reserve(tok_to_max.size());
    out_values.reserve(tok_to_max.size());

    for (const auto& [tok, val] : tok_to_max) {
        out_indices.push_back(tok);
        out_values.push_back(val);
    }
}

// Test utilities for comparing with Python
struct TestVector {
    std::vector<uint32_t> prompt_tokens;
    std::vector<uint32_t> chosen_tokens;
    std::vector<float> expected_u;
    std::vector<std::vector<float>> topk_logits;
    std::vector<std::vector<uint32_t>> topk_indices;
    float temperature;
    float top_p;
    uint32_t top_k;
    float repetition_penalty;
    bool expected_result;
};

TestVector LoadTestVector(const std::string& json_path);
bool SaveTestResults(const std::string& path, const TestVector& results);

} // namespace verification

#endif // BITCOIN_VERIFICATION_UTILS_H
