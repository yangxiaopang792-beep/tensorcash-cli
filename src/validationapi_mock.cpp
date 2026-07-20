// Copyright (c) 2024 TensorCash developers
// Production MockValidationAPI for deterministic testing/functional runs

#include <validationapi_mock.h>

#include <chainparams.h>
#include <common/args.h>
#include <logging.h>
#include <primitives/block.h>

void ValidationAPIMock::SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior)
{
    const uint256 hash = block.GetHash();
    m_captured_.push_back({hash, type, std::chrono::system_clock::now()});
    LogPrintf("ValidationAPIMock: SendApiRequest(block=%s, type=%d, beh=%d)\n",
              hash.ToString(), static_cast<int>(type), static_cast<int>(behavior));
}

void ValidationAPIMock::SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type)
{
    (void)model;
    m_captured_.push_back({req_id, type, std::chrono::system_clock::now()});
    LogPrintf("ValidationAPIMock: SendApiRequest(model_hash=%s model=%s@%s, type=%d)\n",
              req_id.ToString(), model.metadata.model_name, model.metadata.model_commit, static_cast<int>(type));
}

bool ValidationAPIMock::GetRequestStatus(const uint256& id, const ValidationReqType& type, ValidationResponseValue& status, bool async) const
{
    auto hit = m_status_.find(id);
    if (hit != m_status_.end()) {
        auto tit = hit->second.find(type);
        if (tit != hit->second.end()) {
            status = tit->second;
            return true;
        }
    }

    const bool force_mock_external = gArgs.GetBoolArg("-mockval-force-external", false);

    auto fetch_default = [&](const std::optional<ValidationResponseValue>& opt, ValidationResponseValue& out) -> bool {
        if (opt) {
            out = *opt;
            return true;
        }
        return false;
    };

    if (type == ValidationReqType::Model) {
        if (fetch_default(m_default_model_, status)) {
            const_cast<ValidationAPIMock*>(this)->m_status_[id][type] = status;
            return true;
        }
        status = ValidationResponseValue::Not_Checked;
        return false;
    }

    if (type == ValidationReqType::Challenge) {
        if (!async && fetch_default(m_default_challenge_, status)) {
            const_cast<ValidationAPIMock*>(this)->m_status_[id][type] = status;
            return true;
        }
        if (async || force_mock_external) {
            if (fetch_default(m_default_challenge_, status)) return true;
        }
        status = ValidationResponseValue::Not_Checked;
        return false;
    }

    if (async || force_mock_external) {
        switch (type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            if (fetch_default(m_default_quick_, status)) return true;
            break;
        case ValidationReqType::Full:
            if (fetch_default(m_default_full_, status)) return true;
            break;
        case ValidationReqType::Model:
        case ValidationReqType::Challenge:
            break;
        }
    }

    status = ValidationResponseValue::Not_Checked;
    return false;
}

bool ValidationAPIMock::SetRequestStatus(const uint256& id, const ValidationReqType& type, const ValidationResponseValue& status)
{
    m_status_[id][type] = status;
    LogPrintf("ValidationAPIMock: SetRequestStatus(%s, %d, %d)\n",
              id.ToString(), static_cast<int>(type), static_cast<int>(status));
    return true;
}

uint8_t ValidationAPIMock::GetOwnFullStatus(const uint256& id) const
{
    auto hit = m_status_.find(id);
    if (hit != m_status_.end()) {
        auto tit = hit->second.find(ValidationReqType::Full);
        if (tit != hit->second.end()) return static_cast<uint8_t>(tit->second);
    }
    return 0;
}

bool ValidationAPIMock::RemoveRes_Full(const uint256& pid)
{
    auto it = m_status_.find(pid);
    if (it != m_status_.end()) {
        it->second.erase(ValidationReqType::Full);
        if (it->second.empty()) m_status_.erase(it);
        return true;
    }
    return false;
}

void ValidationAPIMock::SetDefaultResponse(ValidationReqType type, ValidationResponseValue value)
{
    switch (type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            m_default_quick_ = value; break;
        case ValidationReqType::Full:
            m_default_full_ = value; break;
        case ValidationReqType::Model:
            m_default_model_ = value; break;
        case ValidationReqType::Challenge:
            m_default_challenge_ = value; break;
    }
}

std::vector<ValidationMockRequest> ValidationAPIMock::GetCapturedRequests() const
{
    return m_captured_;
}

void ValidationAPIMock::ClearCapturedRequests()
{
    m_captured_.clear();
}

void ValidationAPIMock::ClearAll()
{
    m_status_.clear();
    m_captured_.clear();
    m_default_quick_.reset();
    m_default_full_.reset();
    m_default_model_.reset();
    m_default_challenge_.reset();
}
