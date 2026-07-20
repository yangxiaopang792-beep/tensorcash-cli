// proofblob_utils.h
#ifndef BITCOIN_PRIMITIVES_PROOFBLOB_UTILS_H
#define BITCOIN_PRIMITIVES_PROOFBLOB_UTILS_H

#include "primitives/proofblob.h"
#include <chrono>
#include <sstream>

// Utility class for CProofBlob operations
class ProofBlobUtils {
public:
    // Deep comparison of two CProofBlob objects
    static bool Compare(const CProofBlob& a, const CProofBlob& b, std::string* diff = nullptr) {
        std::ostringstream oss;
        bool identical = true;
        
        #define COMPARE_FIELD(field) \
            if (a.field != b.field) { \
                identical = false; \
                oss << #field << ": " << a.field << " != " << b.field << "\n"; \
            }
        
        #define COMPARE_VEC(field) \
            if (a.field != b.field) { \
                identical = false; \
                oss << #field << ": size " << a.field.size() << " != " << b.field.size() << "\n"; \
            }
        
        COMPARE_FIELD(tick);
        COMPARE_FIELD(timestamp);
        COMPARE_VEC(target);
        COMPARE_VEC(vdf);
        COMPARE_VEC(hash);
        COMPARE_VEC(header_prefix);
        COMPARE_FIELD(is_solution);
        COMPARE_FIELD(model_identifier);
        COMPARE_FIELD(compute_precision);
        COMPARE_FIELD(ipfs_cid);
        COMPARE_FIELD(extra_flags);
        COMPARE_FIELD(temperature);
        COMPARE_FIELD(top_p);
        COMPARE_FIELD(top_k);
        COMPARE_FIELD(repetition_penalty);
        COMPARE_VEC(chosen_tokens);
        COMPARE_VEC(chosen_probs);
        COMPARE_VEC(sampling_u);
        COMPARE_VEC(softmax_normalizers);
        COMPARE_VEC(prompt_tokens);
        COMPARE_VEC(pad_mask);
        
        // Compare 2D vectors
        if (a.topk_logits.size() != b.topk_logits.size()) {
            identical = false;
            oss << "topk_logits: rows " << a.topk_logits.size() 
                << " != " << b.topk_logits.size() << "\n";
        }
        
        #undef COMPARE_FIELD
        #undef COMPARE_VEC
        
        if (diff) {
            *diff = oss.str();
        }
        
        return identical;
    }
    
    // Calculate memory usage of a CProofBlob
    static size_t GetMemoryUsage(const CProofBlob& blob) {
        size_t size = sizeof(CProofBlob);
        
        // Add vector capacities
        size += blob.target.capacity() * sizeof(uint8_t);
        size += blob.vdf.capacity() * sizeof(uint8_t);
        size += blob.hash.capacity() * sizeof(uint8_t);
        size += blob.header_prefix.capacity() * sizeof(uint8_t);
        size += blob.model_identifier.capacity();
        size += blob.compute_precision.capacity();
        size += blob.ipfs_cid.capacity();
        size += blob.extra_flags.capacity();
        size += blob.chosen_tokens.capacity() * sizeof(uint32_t);
        size += blob.chosen_probs.capacity() * sizeof(float);
        size += blob.sampling_u.capacity() * sizeof(float);
        size += blob.softmax_normalizers.capacity() * sizeof(float);
        size += blob.prompt_tokens.capacity() * sizeof(uint32_t);
        size += blob.pad_mask.capacity() * sizeof(uint8_t);
        
        // Add 2D vectors
        size += blob.topk_logits.capacity() * sizeof(std::vector<float>);
        for (const auto& row : blob.topk_logits) {
            size += row.capacity() * sizeof(float);
        }
        
        size += blob.topk_indices.capacity() * sizeof(std::vector<uint32_t>);
        for (const auto& row : blob.topk_indices) {
            size += row.capacity() * sizeof(uint32_t);
        }
        
        size += blob.logsumexp_stats.capacity() * sizeof(std::vector<float>);
        for (const auto& row : blob.logsumexp_stats) {
            size += row.capacity() * sizeof(float);
        }
        
        return size;
    }
    
    // Create a summary string of the blob
    static std::string GetSummary(const CProofBlob& blob) {
        std::ostringstream oss;
        oss << "ProofBlob Summary:\n";
        oss << "  Model: " << blob.model_identifier << "\n";
        oss << "  Tick: " << blob.tick << "\n";
        oss << "  Timestamp: " << blob.timestamp 
            << " (" << TimestampToString(blob.timestamp) << ")\n";
        oss << "  Is Solution: " << (blob.is_solution ? "Yes" : "No") << "\n";
        oss << "  Hash: " << HexStr(blob.hash) << "\n";
        oss << "  Temperature: " << blob.temperature << "\n";
        oss << "  Top-p: " << blob.top_p << "\n";
        oss << "  Top-k: " << blob.top_k << "\n";
        oss << "  Tokens: " << blob.chosen_tokens.size() << " chosen, " 
            << blob.prompt_tokens.size() << " prompt\n";
        oss << "  Logits shape: " << blob.topk_logits.size() << " x " 
            << (blob.topk_logits.empty() ? 0 : blob.topk_logits[0].size()) << "\n";
        oss << "  Memory usage: " << GetMemoryUsage(blob) << " bytes\n";
        return oss.str();
    }
    
private:
    static std::string TimestampToString(uint64_t timestamp) {
        auto tp = std::chrono::system_clock::from_time_t(timestamp);
        std::time_t tt = std::chrono::system_clock::to_time_t(tp);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::gmtime(&tt));
        return std::string(buf);
    }
    
    static std::string HexStr(const std::vector<uint8_t>& data) {
        if (data.empty()) return "empty";
        if (data.size() > 4) {
            // Show first 4 bytes for long data
            std::ostringstream oss;
            for (size_t i = 0; i < 4; ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0') 
                    << static_cast<int>(data[i]);
            }
            oss << "... (" << std::dec << data.size() << " bytes)";
            return oss.str();
        }
        // Show all bytes for short data
        std::ostringstream oss;
        for (uint8_t byte : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(byte);
        }
        return oss.str();
    }
};

// Performance profiler for FlatBuffer operations
class FlatBufferProfiler {
    std::chrono::high_resolution_clock::time_point start;
    std::string operation;
    
public:
    explicit FlatBufferProfiler(const std::string& op) : operation(op) {
        start = std::chrono::high_resolution_clock::now();
    }
    
    ~FlatBufferProfiler() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        // Comment out or replace with your logging mechanism
        // LogPrint(BCLog::BENCH, "%s took %lld µs\n", operation.c_str(), duration.count());
        printf("%s took %lld µs\n", operation.c_str(), static_cast<long long>(duration.count()));
    }
};

// Macro for easy profiling
#define PROFILE_FB_OP(op) FlatBufferProfiler _profiler(op)

// Builder pattern for creating test CProofBlob instances
class ProofBlobBuilder {
    CProofBlob blob;
    
public:
    ProofBlobBuilder& withTick(uint64_t tick) {
        blob.tick = tick;
        return *this;
    }
    
    ProofBlobBuilder& withTimestamp(uint64_t timestamp) {
        blob.timestamp = timestamp;
        return *this;
    }
    
    ProofBlobBuilder& withModel(const std::string& model) {
        blob.model_identifier = model;
        return *this;
    }
    
    ProofBlobBuilder& withSolution(bool is_solution) {
        blob.is_solution = is_solution;
        return *this;
    }
    
    ProofBlobBuilder& withHash(const std::vector<uint8_t>& hash) {
        blob.hash = hash;
        return *this;
    }
    
    ProofBlobBuilder& withRandomHash() {
        blob.hash.resize(32);
        for (auto& byte : blob.hash) {
            byte = rand() % 256;
        }
        return *this;
    }
    
    ProofBlobBuilder& withTemperature(float temp) {
        blob.temperature = temp;
        return *this;
    }
    
    ProofBlobBuilder& withTokens(const std::vector<uint32_t>& tokens,
                                  const std::vector<float>& probs) {
        blob.chosen_tokens = tokens;
        blob.chosen_probs = probs;
        return *this;
    }
    
    ProofBlobBuilder& withLogits(size_t rows, size_t cols) {
        blob.topk_logits.resize(rows);
        blob.topk_indices.resize(rows);
        for (size_t i = 0; i < rows; ++i) {
            blob.topk_logits[i].resize(cols);
            blob.topk_indices[i].resize(cols);
            for (size_t j = 0; j < cols; ++j) {
                blob.topk_logits[i][j] = static_cast<float>(i * cols + j) / 100.0f;
                blob.topk_indices[i][j] = i * cols + j;
            }
        }
        return *this;
    }
    
    CProofBlob build() {
        return blob;
    }
};

#endif // BITCOIN_PRIMITIVES_PROOFBLOB_UTILS_H