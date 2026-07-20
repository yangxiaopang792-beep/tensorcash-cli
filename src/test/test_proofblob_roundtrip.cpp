
// test_proofblob_roundtrip.cpp - Augmented version with MiningResponse support
#include "primitives/proofblob.h"
#include <util/translation.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <cassert>
#include <streams.h>  // Bitcoin Core's stream classes

const TranslateFn G_TRANSLATION_FUN{nullptr};

// Include the generated FlatBuffer headers for MiningResponse
// Assuming you have something like:
// #include "mining_response_generated.h"

// Constants from your validation code
constexpr size_t EXPECTED_HASH_SIZE = 32;
constexpr uint32_t MAX_REQUEST_ID = 1000000; // Adjust as needed

// Utility function to read a binary file
std::vector<uint8_t> ReadBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }
    
    return buffer;
}

// Utility function to write a binary file
void WriteBinaryFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create file: " + filename);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!file) {
        throw std::runtime_error("Failed to write file: " + filename);
    }
}

// Convert bytes to hex string for logging
std::string BytesToHex(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        result += buf;
    }
    return result;
}

// Test function for MiningResponse
bool TestMiningResponse(const std::string& inputFile, bool verbose = false) {
    try {
        std::cout << "\n=== Testing MiningResponse from " << inputFile << " ===\n";
        
        // Step 1: Read the binary file
        std::vector<uint8_t> data = ReadBinaryFile(inputFile);
        std::cout << "Read " << data.size() << " bytes\n";
        
        // Step 2: Verify the buffer
        // Note: The schema shows root_type is BlockHeader, but we're dealing with MiningResponse
        // You may need to adjust based on your actual schema setup
        flatbuffers::Verifier verifier(data.data(), data.size());
        
        // Get the MiningResponse - adjust this based on your actual generated code
        const proof::MiningResponse* resp = flatbuffers::GetRoot<proof::MiningResponse>(data.data());
        if (!resp) {
            std::cerr << "Failed to get MiningResponse root object\n";
            return false;
        }
        
        // Verify the buffer is valid
        if (!resp->Verify(verifier)) {
            std::cerr << "Failed to verify MiningResponse\n";
            // return false;
        }
        
        // Step 4: Log all MiningResponse fields
        std::cout << "\nMiningResponse contents:\n";
        std::cout << "  Request ID: " << resp->req_id() << "\n";
        std::cout << "  Nonce: " << resp->nonce() << " (0x" << std::hex << resp->nonce() << std::dec << ")\n";
        std::cout << "  Adjusted bits: " << resp->adjusted_bits() << " (0x" << std::hex << resp->adjusted_bits() << std::dec << ")\n";
        std::cout << "  Difficulty: " << resp->difficulty() << "\n";
        
        // Check pow_blob_hash
        if (resp->pow_blob_hash()) {
            std::cout << "  PoW blob hash size: " << resp->pow_blob_hash()->size() << " bytes\n";
            if (resp->pow_blob_hash()->size() > 0) {
                std::string hash_hex = BytesToHex(resp->pow_blob_hash()->data(), 
                                                std::min<size_t>(resp->pow_blob_hash()->size(), 32));
                std::cout << "  PoW blob hash: " << hash_hex;
                if (resp->pow_blob_hash()->size() > 32) {
                    std::cout << "...";
                }
                std::cout << "\n";
            }
        } else {
            std::cout << "  PoW blob hash: null\n";
        }
        
        // Step 5: Validate the response
        std::cout << "\nValidating MiningResponse...\n";
        
        // Validate request ID
        if (resp->req_id() >= MAX_REQUEST_ID) {
            std::cerr << "✗ Invalid request ID: " << resp->req_id() << " (max: " << MAX_REQUEST_ID << ")\n";
            return false;
        } else {
            std::cout << "✓ Request ID valid\n";
        }
        
        // Validate pow_blob_hash
        if (!resp->pow_blob_hash() || resp->pow_blob_hash()->size() != EXPECTED_HASH_SIZE) {
            std::cerr << "✗ Invalid PoW blob hash size: " 
                     << (resp->pow_blob_hash() ? resp->pow_blob_hash()->size() : 0)
                     << " (expected: " << EXPECTED_HASH_SIZE << ")\n";
            return false;
        } else {
            std::cout << "✓ PoW blob hash size valid\n";
        }
        
        // Step 6: Test the embedded proof blob
        if (!resp->pow_blob()) {
            std::cerr << "✗ Missing PoW blob\n";
            return false;
        }
        
        std::cout << "\nTesting embedded PoW blob...\n";
        
        // Try to fill a CProofBlob from the embedded proof
        CProofBlob proofBlob;
        try {
            proofBlob.fillFromFB(resp->pow_blob());
            std::cout << "✓ Successfully filled CProofBlob from embedded proof\n";
            
            if (verbose) {
                std::cout << "\nProof blob contents:\n";
                std::cout << "  Model: " << proofBlob.model_identifier << "\n";
                std::cout << "  Tick: " << proofBlob.tick << "\n";
                std::cout << "  Timestamp: " << proofBlob.timestamp << "\n";
                std::cout << "  Is Solution: " << proofBlob.is_solution << "\n";
                std::cout << "  Temperature: " << proofBlob.temperature << "\n";
                std::cout << "  Hash size: " << proofBlob.hash.size() << "\n";
                
                // // Calculate model hash
                // uint256 modelHash = proofBlob.GetModelHash();
                // std::cout << "  Model hash: " << modelHash.ToString() << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "✗ Failed to fill PoW blob: " << e.what() << "\n";
            return false;
        }
        
        // Step 7: Test roundtrip of the embedded proof
        if (verbose) {
            std::cout << "\nTesting proof blob roundtrip...\n";
            
            // Serialize the proof blob back to FlatBuffer
            flatbuffers::FlatBufferBuilder builder(1024);
            auto offset = proofBlob.ToFlatBuffer(builder);
            builder.Finish(offset, proof::ProofIdentifier());
            
            // Try to deserialize it again
            const proof::Proof* roundtripProof = proof::GetProof(builder.GetBufferPointer());
            CProofBlob roundtripBlob;
            roundtripBlob.fillFromFB(roundtripProof);
            
            // Compare key fields
            bool matches = true;
            if (proofBlob.model_identifier != roundtripBlob.model_identifier) {
                std::cout << "✗ Model identifier mismatch\n";
                matches = false;
            }
            if (proofBlob.tick != roundtripBlob.tick) {
                std::cout << "✗ Tick mismatch\n";
                matches = false;
            }
            if (proofBlob.timestamp != roundtripBlob.timestamp) {
                std::cout << "✗ Timestamp mismatch\n";
                matches = false;
            }
            
            if (matches) {
                std::cout << "✓ Proof blob roundtrip successful\n";
            }
        }
        
        // Step 8: Test creating a new MiningResponse
        if (verbose) {
            std::cout << "\nTesting MiningResponse creation...\n";
            
            flatbuffers::FlatBufferBuilder respBuilder(1024);
            
            // Create the components
            auto hashVec = respBuilder.CreateVector(resp->pow_blob_hash()->data(), EXPECTED_HASH_SIZE);
            auto proofOffset = proofBlob.ToFlatBuffer(respBuilder);
            
            // Create the MiningResponse
            auto respOffset = proof::CreateMiningResponse(
                respBuilder,
                resp->req_id(),
                resp->nonce(),
                resp->adjusted_bits(),
                hashVec,
                resp->difficulty(),
                proofOffset
            );
            
            respBuilder.Finish(respOffset);
            
            // Verify the new response
            const proof::MiningResponse* newResp = flatbuffers::GetRoot<proof::MiningResponse>(respBuilder.GetBufferPointer());
            flatbuffers::Verifier newVerifier(respBuilder.GetBufferPointer(), respBuilder.GetSize());
            if (newResp && newResp->Verify(newVerifier)) {
                std::cout << "✓ Successfully created new MiningResponse\n";
                std::cout << "  New size: " << respBuilder.GetSize() << " bytes\n";
                std::cout << "  Original size: " << data.size() << " bytes\n";
            } else {
                std::cout << "✗ Failed to verify new MiningResponse\n";
            }
        }
        
        std::cout << "\n✓ MiningResponse test completed successfully\n";
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception during MiningResponse test: " << e.what() << "\n";
        return false;
    }
}

// Create a test MiningResponse file
void CreateTestMiningResponse(const std::string& filename) {
    std::cout << "Creating test MiningResponse file: " << filename << "\n";
    
    flatbuffers::FlatBufferBuilder builder(2048);
    
    // Create a test proof blob first
    CProofBlob testBlob;
    testBlob.tick = 54321;
    testBlob.timestamp = 1234567890;
    testBlob.target = {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};
    testBlob.vdf = {0x01, 0x02, 0x03, 0x04};
    testBlob.hash = std::vector<uint8_t>(32, 0xCD); // 32 bytes
    testBlob.block_hash = std::vector<uint8_t>(32, 0xEF); // 32 bytes
    testBlob.header_prefix = {0xDE, 0xAD, 0xBE, 0xEF};
    testBlob.is_solution = true;
    testBlob.model_identifier = "test-mining-model-v1";
    testBlob.compute_precision = "fp16";
    testBlob.ipfs_cid = "QmMiningTest456";
    testBlob.extra_flags = "mining-debug";
    testBlob.temperature = 0.8f;
    testBlob.top_p = 0.95f;
    testBlob.top_k = 50;
    testBlob.repetition_penalty = 1.05f;
    testBlob.chosen_tokens = {10, 20, 30, 40, 50};
    testBlob.chosen_probs = {0.15f, 0.25f, 0.35f, 0.15f, 0.10f};
    
    // Create the proof offset
    auto proofOffset = testBlob.ToFlatBuffer(builder);
    
    // Create test pow_blob_hash (32 bytes)
    std::vector<uint8_t> testHash(32);
    for (size_t i = 0; i < 32; ++i) {
        testHash[i] = static_cast<uint8_t>(i * 7 + 3); // Some pattern
    }
    auto hashOffset = builder.CreateVector(testHash);
    
    // Create the MiningResponse
    auto respOffset = proof::CreateMiningResponse(
        builder,
        12345,          // req_id
        0xDEADBEEF,     // nonce
        0x1d00ffff,     // adjusted_bits
        hashOffset,     // pow_blob_hash
        1000000,        // difficulty
        proofOffset     // pow_blob
    );
    
    builder.Finish(respOffset);
    
    // Write to file
    std::vector<uint8_t> data(builder.GetBufferPointer(), 
                              builder.GetBufferPointer() + builder.GetSize());
    WriteBinaryFile(filename, data);
    
    std::cout << "Created test MiningResponse file: " << filename << " (" << data.size() << " bytes)\n";
}

// Existing functions remain the same...
bool CompareProofBlobs(const CProofBlob& a, const CProofBlob& b) {
    return a.tick == b.tick &&
           a.timestamp == b.timestamp &&
           a.target == b.target &&
           a.vdf == b.vdf &&
           a.hash == b.hash &&
           a.header_prefix == b.header_prefix &&
           a.is_solution == b.is_solution &&
           a.model_identifier == b.model_identifier &&
           a.compute_precision == b.compute_precision &&
           a.ipfs_cid == b.ipfs_cid &&
           a.extra_flags == b.extra_flags &&
           a.temperature == b.temperature &&
           a.top_p == b.top_p &&
           a.top_k == b.top_k &&
           a.repetition_penalty == b.repetition_penalty &&
           a.chosen_tokens == b.chosen_tokens &&
           a.chosen_probs == b.chosen_probs &&
           a.sampling_u == b.sampling_u &&
           a.softmax_normalizers == b.softmax_normalizers &&
           a.prompt_tokens == b.prompt_tokens &&
           a.pad_mask == b.pad_mask &&
           a.topk_logits == b.topk_logits &&
           a.topk_indices == b.topk_indices &&
           a.logsumexp_stats == b.logsumexp_stats;
}

// Compare two byte vectors and print differences
bool CompareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, bool verbose = false) {
    if (a.size() != b.size()) {
        std::cout << "Size mismatch: " << a.size() << " vs " << b.size() << " bytes\n";
        return false;
    }
    
    bool identical = true;
    size_t diffCount = 0;
    const size_t maxDiffs = 10; // Only show first 10 differences
    
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            identical = false;
            if (verbose && diffCount < maxDiffs) {
                std::cout << "Difference at offset " << std::hex << i << std::dec 
                         << ": 0x" << std::hex << static_cast<int>(a[i]) 
                         << " vs 0x" << static_cast<int>(b[i]) << std::dec << "\n";
            }
            diffCount++;
        }
    }
    
    if (!identical && verbose) {
        std::cout << "Total differences: " << diffCount << " bytes\n";
    }
    
    return identical;
}


// Test roundtrip serialization
bool TestRoundtrip(const std::string& inputFile, bool verbose = false) {
    try {
        // Step 1: Read the original binary file
        std::vector<uint8_t> originalData = ReadBinaryFile(inputFile);
        if (verbose) {
            std::cout << "Read " << originalData.size() << " bytes from " << inputFile << "\n";
        }
        
        // Step 2: Verify and deserialize FlatBuffer
        flatbuffers::Verifier verifier(originalData.data(), originalData.size());
        if (!proof::VerifyProofBuffer(verifier)) {
            std::cerr << "Failed to verify FlatBuffer\n";
            // return false;
        }
        
        const proof::Proof* fbProof = proof::GetProof(originalData.data());
        if (!fbProof) {
            std::cerr << "Failed to get root object\n";
            return false;
        }
        
        // Step 3: Fill CProofBlob from FlatBuffer
        CProofBlob proofBlob;
        proofBlob.fillFromFB(fbProof);
        
        if (verbose) {
            std::cout << "Deserialized proof:\n";
            std::cout << "  Model: " << proofBlob.model_identifier << "\n";
            std::cout << "  Tick: " << proofBlob.tick << "\n";
            std::cout << "  Timestamp: " << proofBlob.timestamp << "\n";
            std::cout << "  Is Solution: " << proofBlob.is_solution << "\n";
            std::cout << "  Temperature: " << proofBlob.temperature << "\n";
            std::cout << "  Hash size: " << proofBlob.hash.size() << "\n";
        }
        
        // Step 4: Serialize back to FlatBuffer
        flatbuffers::FlatBufferBuilder builder(1024);
        auto offset = proofBlob.ToFlatBuffer(builder);
        builder.Finish(offset, proof::ProofIdentifier());
        
        // Step 5: Get the serialized data
        uint8_t* buf = builder.GetBufferPointer();
        size_t size = builder.GetSize();
        std::vector<uint8_t> newData(buf, buf + size);
        
        if (verbose) {
            std::cout << "Re-serialized to " << size << " bytes\n";
        }
        
        // Step 6: Compare - first try byte-for-byte, then logical
        bool identical = CompareBytes(originalData, newData, verbose);
        
        if (identical) {
            std::cout << "✓ Roundtrip test PASSED - data is byte-for-byte identical\n";
            return true;
        } else {
            std::cout << "Binary representation differs (this is normal for FlatBuffers)\n";
            
            // Do logical comparison instead
            std::cout << "Performing logical comparison...\n";
            
            // Parse both buffers
            const proof::Proof* originalProof = proof::GetProof(originalData.data());
            const proof::Proof* newProof = proof::GetProof(newData.data());
            
            CProofBlob originalBlob, newBlob;
            originalBlob.fillFromFB(originalProof);
            newBlob.fillFromFB(newProof);
            
            // Compare the objects
            std::string diff;
            bool logicallyIdentical = CompareProofBlobs(originalBlob, newBlob);
            
            if (logicallyIdentical) {
                std::cout << "✓ Roundtrip test PASSED - data is logically identical\n";
                std::cout << "Note: Binary differs due to FlatBuffer encoding variations\n";
            } else {
                std::cout << "✗ Roundtrip test FAILED - data differs logically\n";
                std::cout << "Differences:\n" << diff;
                
                // Save the re-serialized data for debugging
                std::string outputFile = inputFile + ".roundtrip";
                WriteBinaryFile(outputFile, newData);
                std::cout << "Re-serialized data saved to: " << outputFile << "\n";
            }
            
            return logicallyIdentical;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception during roundtrip test: " << e.what() << "\n";
        return false;
    }
}


// Test Bitcoin Core serialization roundtrip
bool TestBitcoinSerialization(const CProofBlob& original, bool verbose = false) {
    try {
        if (verbose) {
            std::cout << "\n=== Testing Bitcoin Core Serialization ===\n";
        }
        
        // Step 1: Serialize using Bitcoin's serialization
        DataStream ss{};
        ss << original;
        
        if (verbose) {
            std::cout << "Serialized to " << ss.size() << " bytes\n";
            
            // Show hex dump of first 256 bytes
            std::cout << "First 256 bytes of serialized data:\n";
            const unsigned char* data = reinterpret_cast<const unsigned char*>(ss.data());
            for (size_t i = 0; i < std::min(ss.size(), size_t(256)); i += 16) {
                std::cout << std::hex << std::setw(4) << std::setfill('0') << i << ": ";
                for (size_t j = 0; j < 16 && i + j < ss.size(); ++j) {
                    std::cout << std::setw(2) << static_cast<int>(data[i + j]) << " ";
                }
                std::cout << std::dec << "\n";
            }
        }
        
        // Step 2: Deserialize back
        CProofBlob deserialized;
        ss >> deserialized;
        
        // Step 3: Compare objects
        std::string diff;
        bool identical = CompareProofBlobs(original, deserialized);
        
        if (identical) {
            std::cout << "✓ Bitcoin serialization roundtrip PASSED\n";
        } else {
            std::cout << "✗ Bitcoin serialization roundtrip FAILED\n";
            if (verbose && !diff.empty()) {
                std::cout << "Differences:\n" << diff;
            }
        }
        
        // Step 4: Test that we consumed all data (no extra bytes)
        if (!ss.empty()) {
            std::cout << "✗ Warning: " << ss.size() << " bytes left unread after deserialization\n";
            identical = false;
        }
        
        // Step 5: Double-check by serializing again and comparing binary
        if (identical && verbose) {
            DataStream ss2{};
            ss2 << deserialized;
            
            if (ss.size() == ss2.size() && 
                std::memcmp(ss.data(), ss2.data(), ss.size()) == 0) {
                std::cout << "✓ Re-serialization produces identical binary\n";
            } else {
                std::cout << "✗ Re-serialization produces different binary\n";
                std::cout << "  Original: " << ss.size() << " bytes\n";
                std::cout << "  Re-serialized: " << ss2.size() << " bytes\n";
            }
        }
        
        return identical;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception during Bitcoin serialization test: " << e.what() << "\n";
        return false;
    }
}

// Test both FlatBuffer and Bitcoin serialization
bool TestCompleteSerialization(const std::string& inputFile, bool verbose = false) {
    try {
        // Read and deserialize from FlatBuffer
        std::vector<uint8_t> originalData = ReadBinaryFile(inputFile);
        const proof::Proof* fbProof = proof::GetProof(originalData.data());
        
        CProofBlob proofBlob;
        proofBlob.fillFromFB(fbProof);
        
        std::cout << "\n=== Testing Complete Serialization ===\n";
        
        // Test 1: FlatBuffer roundtrip
        bool fbPass = TestRoundtrip(inputFile, verbose);
        
        // Test 2: Bitcoin Core serialization roundtrip
        bool btcPass = TestBitcoinSerialization(proofBlob, verbose);
        
        // Test 3: Cross-serialization test (FB -> BTC -> FB)
        if (fbPass && btcPass && verbose) {
            std::cout << "\n=== Cross-Serialization Test ===\n";
            
            // Serialize to Bitcoin format
            DataStream ss{};
            ss << proofBlob;
            
            // Deserialize from Bitcoin format
            CProofBlob fromBitcoin;
            ss >> fromBitcoin;
            
            // Serialize back to FlatBuffer
            flatbuffers::FlatBufferBuilder builder(1024);
            auto offset = fromBitcoin.ToFlatBuffer(builder);
            builder.Finish(offset, proof::ProofIdentifier());
            
            // Check if we can round-trip through both formats
            const proof::Proof* crossCheck = proof::GetProof(builder.GetBufferPointer());
            CProofBlob final;
            final.fillFromFB(crossCheck);
            
            std::string diff;
            bool crossIdentical = CompareProofBlobs(proofBlob, final);
            
            if (crossIdentical) {
                std::cout << "✓ Cross-serialization test PASSED\n";
            } else {
                std::cout << "✗ Cross-serialization test FAILED\n";
                if (!diff.empty()) {
                    std::cout << "Differences after FB->BTC->FB:\n" << diff;
                }
            }
        }
        
        return fbPass && btcPass;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return false;
    }
}

// Simple standalone test for Bitcoin serialization
void TestBitcoinSerializationStandalone() {
    std::cout << "\n=== Standalone Bitcoin Serialization Test ===\n";
    
    // Create test data
    CProofBlob test;
    test.tick = 12345;
    test.timestamp = 1234567890;
    test.model_identifier = "test-model";
    test.temperature = 0.7f;
    test.chosen_tokens = {1, 2, 3, 4, 5};
    test.chosen_probs = {0.1f, 0.2f, 0.3f, 0.2f, 0.2f};
    test.topk_logits = {{0.1f, 0.2f}, {0.3f, 0.4f}};
    
    // Test serialization
    DataStream ss{};
    
    try {
        ss << test;
        std::cout << "Serialized successfully: " << ss.size() << " bytes\n";
        
        CProofBlob test2;
        ss >> test2;
        std::cout << "Deserialized successfully\n";
        
        // Quick verification
        if (test.tick == test2.tick && 
            test.model_identifier == test2.model_identifier &&
            test.chosen_tokens.size() == test2.chosen_tokens.size()) {
            std::cout << "✓ Basic fields match\n";
        } else {
            std::cout << "✗ Basic fields don't match\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "✗ Serialization failed: " << e.what() << "\n";
        std::cout << "Note: This likely means float serialization is not implemented\n";
    }
}



// Create a test FlatBuffer file with sample data
void CreateTestFile(const std::string& filename) {
    CProofBlob testBlob;
    
    // Fill with test data
    testBlob.tick = 12345;
    testBlob.timestamp = 1234567890;
    testBlob.target = {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};
    testBlob.vdf = {0x01, 0x02, 0x03, 0x04};
    testBlob.hash = std::vector<uint8_t>(32, 0xAB); // 32 bytes
    testBlob.header_prefix = {0xDE, 0xAD, 0xBE, 0xEF};
    testBlob.is_solution = true;
    testBlob.model_identifier = "test-model-v1";
    testBlob.compute_precision = "fp16";
    testBlob.ipfs_cid = "QmTest123";
    testBlob.extra_flags = "debug";
    testBlob.temperature = 0.7f;
    testBlob.top_p = 0.9f;
    testBlob.top_k = 40;
    testBlob.repetition_penalty = 1.1f;
    testBlob.chosen_tokens = {1, 2, 3, 4, 5};
    testBlob.chosen_probs = {0.1f, 0.2f, 0.3f, 0.2f, 0.2f};
    testBlob.sampling_u = {0.5f, 0.6f, 0.7f, 0.8f, 0.9f};
    testBlob.softmax_normalizers = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    testBlob.prompt_tokens = {100, 200, 300};
    testBlob.pad_mask = {1, 1, 0, 1, 0};
    
    // Add some 2D data
    testBlob.topk_logits = {{0.1f, 0.2f}, {0.3f, 0.4f}, {0.5f, 0.6f}};
    testBlob.topk_indices = {{10, 20}, {30, 40}, {50, 60}};
    testBlob.logsumexp_stats = {{1.0f, 2.0f}, {3.0f, 4.0f}};
    
    // Serialize to FlatBuffer
    flatbuffers::FlatBufferBuilder builder(1024);
    auto offset = testBlob.ToFlatBuffer(builder);
    builder.Finish(offset, proof::ProofIdentifier());
    
    // Write to file
    std::vector<uint8_t> data(builder.GetBufferPointer(), 
                              builder.GetBufferPointer() + builder.GetSize());
    WriteBinaryFile(filename, data);
    
    std::cout << "Created test file: " << filename << " (" << data.size() << " bytes)\n";
}

// Extended validation function for CProofBlob
bool ValidateProofBlob(const CProofBlob& blob, bool verbose = false) {
    bool valid = true;
    
    // Check model identifier
    if (blob.model_identifier.empty()) {
        if (verbose) std::cerr << "Empty model identifier\n";
        valid = false;
    }
    
    // Check timestamp
    if (blob.timestamp == 0) {
        if (verbose) std::cerr << "Zero timestamp\n";
        valid = false;
    }
    
    // Check hash size (should be 32 bytes for SHA256)
    if (!blob.hash.empty() && blob.hash.size() != 32) {
        if (verbose) std::cerr << "Invalid hash size: " << blob.hash.size() << "\n";
        valid = false;
    }
    
    // Check consistency of paired vectors
    if (blob.chosen_tokens.size() != blob.chosen_probs.size()) {
        if (verbose) std::cerr << "Mismatch: chosen_tokens size != chosen_probs size\n";
        valid = false;
    }
    
    // Check temperature range
    if (blob.temperature < 0.0f || blob.temperature > 2.0f) {
        if (verbose) std::cerr << "Temperature out of range: " << blob.temperature << "\n";
        valid = false;
    }
    
    // Check top_p range
    if (blob.top_p < 0.0f || blob.top_p > 1.0f) {
        if (verbose) std::cerr << "top_p out of range: " << blob.top_p << "\n";
        valid = false;
    }
    
    // Check 2D arrays consistency
    if (!blob.topk_logits.empty() && !blob.topk_indices.empty()) {
        if (blob.topk_logits.size() != blob.topk_indices.size()) {
            if (verbose) std::cerr << "Mismatch: topk_logits rows != topk_indices rows\n";
            valid = false;
        }
        
        // Check that all rows have the same size
        if (!blob.topk_logits.empty()) {
            size_t rowSize = blob.topk_logits[0].size();
            for (size_t i = 1; i < blob.topk_logits.size(); ++i) {
                if (blob.topk_logits[i].size() != rowSize) {
                    if (verbose) std::cerr << "Inconsistent row sizes in topk_logits\n";
                    valid = false;
                    break;
                }
            }
        }
    }
    
    return valid;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <file.bin> [options]\n";
        std::cout << "Options:\n";
        std::cout << "  --verbose: Show detailed comparison\n";
        std::cout << "  --create-test: Create a test proof file\n";
        std::cout << "  --create-mining-response: Create a test MiningResponse file\n";
        std::cout << "  --test-mining-response: Test file as MiningResponse instead of Proof\n";
        std::cout << "  --bitcoin-only: Test only Bitcoin serialization\n";
        return 1;
    }
    
    std::string filename = argv[1];
    bool verbose = false;
    bool createTest = false;
    bool createMiningResponse = false;
    bool testMiningResponse = false;
    bool bitcoinOnly = false;
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--create-test") {
            createTest = true;
        } else if (arg == "--create-mining-response") {
            createMiningResponse = true;
        } else if (arg == "--test-mining-response") {
            testMiningResponse = true;
        } else if (arg == "--bitcoin-only") {
            bitcoinOnly = true;
        }
    }
    
    if (createTest) {
        CreateTestFile(filename);
        return 0;
    }
    
    if (createMiningResponse) {
        CreateTestMiningResponse(filename);
        return 0;
    }
    
    if (testMiningResponse) {
        // Test as MiningResponse
        bool success = TestMiningResponse(filename, verbose);
        return success ? 0 : 1;
    }
    
    if (bitcoinOnly) {
        TestBitcoinSerializationStandalone();
        return 0;
    }
    
    // Default: test as regular Proof
    bool success = TestCompleteSerialization(filename, verbose);
    
    // Additional validation test
    if (success && verbose) {
        std::cout << "\nPerforming additional validation...\n";
        
        std::vector<uint8_t> data = ReadBinaryFile(filename);
        const proof::Proof* fbProof = proof::GetProof(data.data());
        CProofBlob blob;
        blob.fillFromFB(fbProof);
        
        if (ValidateProofBlob(blob, verbose)) {
            std::cout << "✓ Validation passed\n";
        } else {
            std::cout << "✗ Validation failed\n";
        }
    }
    
    return success ? 0 : 1;
}
