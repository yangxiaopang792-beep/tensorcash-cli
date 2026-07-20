// Lightweight C-linkage shims to access node-only globals from modules
// that cannot link against bitcoin_node directly. Declarations are used
// as weak references by consumers so missing implementations won't break
// link of tools that don't include node components.

#ifndef BITCOIN_NODE_MODEL_VALIDATION_SHIMS_H
#define BITCOIN_NODE_MODEL_VALIDATION_SHIMS_H

#include <stdint.h>

#include <optional>

#include <uint256.h>
#include <validationapi.h>
#include <modeldb.h>

extern "C" {
// Returns true if model exists. Weak referenced by callers.
bool Shim_ModelDB_Exists(const uint256& model_hash);

// Query validation status for a model. Returns true if a status was available.
bool Shim_Validation_GetRequestStatus_Model(const uint256& id, ValidationResponseValue* status, bool async);

// Send validation request for a model.
void Shim_Validation_SendApiRequest_Model(const ModelRecord* model);
}

#endif // BITCOIN_NODE_MODEL_VALIDATION_SHIMS_H

