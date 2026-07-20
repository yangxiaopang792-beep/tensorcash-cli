// Copyright (c) 2024 TensorCash developers
// Production MockValidationAPI for deterministic testing/functional runs

#ifndef BITCOIN_NODE_VALIDATIONAPI_MOCK_H
#define BITCOIN_NODE_VALIDATIONAPI_MOCK_H

#include <validationapi.h>
#include <uint256.h>
#include <memory>
#include <unordered_map>
#include <vector>
#include <optional>
#include <chrono>

// Track validation requests for assertions
struct ValidationMockRequest {
    uint256 hash;
    ValidationReqType type;
    std::chrono::system_clock::time_point timestamp;
};

// Production mock implementation of IValidationAPI (no threads/ZMQ)
class ValidationAPIMock : public IValidationAPI {
private:
    std::unordered_map<uint256, std::map<ValidationReqType, ValidationResponseValue>, Hasher> m_status_;
    mutable std::vector<ValidationMockRequest> m_captured_;
    std::optional<ValidationResponseValue> m_default_quick_;
    std::optional<ValidationResponseValue> m_default_full_;
    std::optional<ValidationResponseValue> m_default_model_;
    std::optional<ValidationResponseValue> m_default_challenge_;

public:
    ValidationAPIMock() = default;
    ~ValidationAPIMock() override = default;

    // IValidationAPI
    void SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) override;
    void SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) override;
    bool GetRequestStatus(const uint256& id, const ValidationReqType& type, ValidationResponseValue& status, bool async = true) const override;
    bool SetRequestStatus(const uint256& id, const ValidationReqType& type, const ValidationResponseValue& status) override;
    uint8_t GetOwnFullStatus(const uint256& id) const override;
    bool RemoveRes_Full(const uint256& pid) override;
    void RecordPeerFullStatus(const uint256& id, const std::string& peer_id, ValidationResponseValue peer_status) override {}
    bool Initialize() override { return true; }
    bool IsFullQueueEmpty() const override { return true; }
    bool ShouldDeferMissingFullValidation() const override { return false; }
    bool UsesRequestStatusForBlockProcessing() const override { return true; }

    // Control helpers
    void SetDefaultResponse(ValidationReqType type, ValidationResponseValue value);
    std::vector<ValidationMockRequest> GetCapturedRequests() const;
    void ClearCapturedRequests();
    void ClearAll();
};

#endif // BITCOIN_NODE_VALIDATIONAPI_MOCK_H
