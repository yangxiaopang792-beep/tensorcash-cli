#include <node/model_validation_shims.h>
#include <wallet/rpc/api_model_registration.h>

extern std::unique_ptr<CModelDB> g_modeldb;
extern std::unique_ptr<IValidationAPI> g_ValidationApi;

extern "C" bool Shim_ModelDB_Exists(const uint256& model_hash)
{
    if (!g_modeldb) return false;
    return g_modeldb->Exists(model_hash);
}

extern "C" bool Shim_Validation_GetRequestStatus_Model(const uint256& id, ValidationResponseValue* status, bool async)
{
    if (!g_ValidationApi || !status) return false;
    return g_ValidationApi->GetRequestStatus(id, ValidationReqType::Model, *status, async);
}

extern "C" void Shim_Validation_SendApiRequest_Model(const ModelRecord* model)
{
    if (!g_ValidationApi || !model) return;
    const uint256 model_hash = HashSHA256(model->metadata);
    g_ValidationApi->SendApiRequest(model_hash, *model, ValidationReqType::Model);
}
