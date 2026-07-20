// Copyright (c) 2024 TensorCash developers
// Mock ValidationAPI implementation

#include <test/util/mock_validation_api.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <modeldb.h>

extern std::unique_ptr<IValidationAPI> g_ValidationApi;

void MockValidationAPI::SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior)
{
    // Track this request
    uint256 hash = block.GetHash();
    m_captured_requests.push_back({hash, type, std::chrono::system_clock::now()});
    
    // Log disabled in mock - LogPrint not available in test context
}

void MockValidationAPI::SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type)
{
    (void)model;
    // Track this request
    m_captured_requests.push_back({req_id, type, std::chrono::system_clock::now()});
    
    // Log disabled in mock - LogPrint not available in test context
}

bool MockValidationAPI::TryLocalQuickVerdict(const CBlock& block, ValidationResponseValue& status)
{
    (void)block;
    if (!m_local_quick) {
        return false;
    }
    status = *m_local_quick;
    return true;
}

bool MockValidationAPI::GetRequestStatus(const uint256& id, const ValidationReqType& type, ValidationResponseValue& status, bool async) const
{
    // Check specific status first
    auto hash_it = m_status.find(id);
    if (hash_it != m_status.end()) {
        auto type_it = hash_it->second.find(type);
        if (type_it != hash_it->second.end()) {
            status = type_it->second;
            // Found status
            return true;
        }
    }
    
    // Fall back to defaults if set
    if ((type == ValidationReqType::Quick || type == ValidationReqType::Quick_Smell) && m_default_quick) {
        status = *m_default_quick;
        return true;
    }
    if (type == ValidationReqType::Full && m_default_full) {
        status = *m_default_full;
        return true;
    }
    if (type == ValidationReqType::Model && m_default_model) {
        status = *m_default_model;
        return true;
    }
    if (type == ValidationReqType::Challenge && m_default_challenge) {
        status = *m_default_challenge;
        return true;
    }

    // No status available - set to Not_Checked to avoid undefined reads
    status = ValidationResponseValue::Not_Checked;
    return false;
}

bool MockValidationAPI::SetRequestStatus(const uint256& id, const ValidationReqType& type, const ValidationResponseValue& status)
{
    m_status[id][type] = status;
    // Status set
    return true;
}

uint8_t MockValidationAPI::GetOwnFullStatus(const uint256& id) const
{
    auto hash_it = m_status.find(id);
    if (hash_it != m_status.end()) {
        auto type_it = hash_it->second.find(ValidationReqType::Full);
        if (type_it != hash_it->second.end()) {
            // Return status as flags (simplified for mock)
            return static_cast<uint8_t>(type_it->second);
        }
    }
    return 0; // Not validated
}

bool MockValidationAPI::RemoveRes_Full(const uint256& pid)
{
    auto it = m_status.find(pid);
    if (it != m_status.end()) {
        it->second.erase(ValidationReqType::Full);
        if (it->second.empty()) {
            m_status.erase(it);
        }
        // Removed Full status
        return true;
    }
    return false;
}

void MockValidationAPI::SetDefaultResponse(ValidationReqType type, ValidationResponseValue value)
{
    switch (type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            m_default_quick = value;
            break;
        case ValidationReqType::Full:
            m_default_full = value;
            break;
        case ValidationReqType::Model:
            m_default_model = value;
            break;
        case ValidationReqType::Challenge:
            m_default_challenge = value;
            break;
    }
}

void MockValidationAPI::SetLocalQuickResponse(ValidationResponseValue value)
{
    m_local_quick = value;
}

std::vector<ValidationRequest> MockValidationAPI::GetCapturedRequests() const
{
    return m_captured_requests;
}

void MockValidationAPI::ClearCapturedRequests()
{
    m_captured_requests.clear();
}

void MockValidationAPI::ClearAll()
{
    m_status.clear();
    m_captured_requests.clear();
    m_default_quick.reset();
    m_default_full.reset();
    m_default_model.reset();
    m_default_challenge.reset();
    m_local_quick.reset();
}

// ScopedValidationApiMock implementation

ScopedValidationApiMock::ScopedValidationApiMock()
{
    // Save previous API (may be nullptr)
    m_previous = std::move(g_ValidationApi);
    
    // Create and install the mock
    auto mock = std::make_unique<MockValidationAPI>();
    m_mock = mock.get(); // Keep raw pointer for access
    g_ValidationApi = std::move(mock); // Transfer ownership to global
}

ScopedValidationApiMock::~ScopedValidationApiMock()
{
    // Clear our raw pointer (g_ValidationApi owns it)
    m_mock = nullptr;
    
    // Restore previous API
    g_ValidationApi = std::move(m_previous);
}

// ScopedGenesisApproval implementation  

ScopedGenesisApproval::ScopedGenesisApproval(const CChainParams& params)
    : ScopedValidationApiMock()
{
    // Auto-approve genesis block for Quick_Smell validation
    const uint256& genesis_hash = params.GenesisBlock().GetHash();
    if (m_mock) {
        m_mock->SetRequestStatus(genesis_hash, 
                                ValidationReqType::Quick_Smell,
                                ValidationResponseValue::Quick_OK_Smell_OK);
        
        // Genesis pre-approved for chain
    }
}
