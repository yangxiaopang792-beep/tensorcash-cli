// Copyright (c) 2024 TensorCash developers
// Mock ValidationAPI for deterministic testing

#ifndef BITCOIN_TEST_UTIL_MOCK_VALIDATION_API_H
#define BITCOIN_TEST_UTIL_MOCK_VALIDATION_API_H

#include <validationapi.h>
#include <uint256.h>
#include <memory>
#include <unordered_map>
#include <vector>
#include <optional>
#include <chrono>

class CChainParams;

// Track validation requests for assertions
struct ValidationRequest {
    uint256 hash;
    ValidationReqType type;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * MockValidationAPI provides deterministic validation responses for testing.
 * No external dependencies, no ZMQ, no threads - pure in-process mock.
 */
class MockValidationAPI : public IValidationAPI {
private:
    // Per-hash status storage - using Hasher from validationapi.h
    std::unordered_map<uint256, std::map<ValidationReqType, ValidationResponseValue>, Hasher> m_status;
    
    // Request tracking for assertions
    mutable std::vector<ValidationRequest> m_captured_requests;
    
    // Optional autopilot defaults
    std::optional<ValidationResponseValue> m_default_quick;
    std::optional<ValidationResponseValue> m_default_full;
    std::optional<ValidationResponseValue> m_default_model;
    std::optional<ValidationResponseValue> m_default_challenge;
    std::optional<ValidationResponseValue> m_local_quick;

public:
    MockValidationAPI() = default;
    ~MockValidationAPI() override = default;

    // IValidationAPI interface
    void SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) override;
    void SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) override;
    bool TryLocalQuickVerdict(const CBlock& block, ValidationResponseValue& status) override;
    bool GetRequestStatus(const uint256& id, const ValidationReqType& type, ValidationResponseValue& status, bool async = true) const override;
    bool SetRequestStatus(const uint256& id, const ValidationReqType& type, const ValidationResponseValue& status) override;
    uint8_t GetOwnFullStatus(const uint256& id) const override;
    bool RemoveRes_Full(const uint256& pid) override;
    void RecordPeerFullStatus(const uint256& id, const std::string& peer_id, ValidationResponseValue peer_status) override {}
    bool Initialize() override { return true; }
    bool IsFullQueueEmpty() const override { return true; }
    bool ShouldDeferMissingFullValidation() const override { return false; }
    bool UsesRequestStatusForBlockProcessing() const override { return true; }
    
    // Test control methods
    void SetDefaultResponse(ValidationReqType type, ValidationResponseValue value);
    void SetLocalQuickResponse(ValidationResponseValue value);
    std::vector<ValidationRequest> GetCapturedRequests() const;
    void ClearCapturedRequests();
    void ClearAll();
};

/**
 * RAII wrapper that replaces g_ValidationApi for the lifetime of the object.
 * Automatically restores the previous API on destruction.
 */
class ScopedValidationApiMock {
protected:
    std::unique_ptr<IValidationAPI> m_previous;
    MockValidationAPI* m_mock; // Non-owning pointer (g_ValidationApi owns it)
    
public:
    ScopedValidationApiMock();
    ~ScopedValidationApiMock();
    
    MockValidationAPI* operator->() { return m_mock; }
    MockValidationAPI& operator*() { return *m_mock; }
    MockValidationAPI* get() { return m_mock; }
};

/**
 * Specialized helper that auto-approves genesis block for a chain.
 * Essential for TensorMain/TensorTest fixture initialization.
 */
class ScopedGenesisApproval : public ScopedValidationApiMock {
public:
    explicit ScopedGenesisApproval(const CChainParams& params);
};

#endif // BITCOIN_TEST_UTIL_MOCK_VALIDATION_API_H
