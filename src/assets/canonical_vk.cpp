// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/canonical_vk.h>

namespace assets {

const std::map<uint256, CanonicalVkInfo>& CanonicalVkAllowlist()
{
    // Genesis-blessed depth-8 HDv1 verifying key.
    //
    // Derivation (consensus-critical — keep this recipe with the value):
    //   vk_data = the C++/BLST custom-serialized VK (the bytes registered on-chain and
    //             read back by ReadZkVerifyingKey), i.e. the `vk_hex` in
    //             shared-utils/kyc-prover/vectors_hd_v1/golden_vectors_hd_v1.json
    //             (674 bytes; identical across all golden vectors — one trusted setup).
    //   vk_commitment = SHA256(SHA256(vk_data))   [matches registerasset, assets.cpp:1702]
    //   That digest fills uint256::begin() in output order:
    //       begin-order = d818e84e52a863309dd9e2ba5240924fcafd585b7e21d12b0c2e5631a013e245
    //   The uint256{"..."} literal below is its byte-reversed display form, so the
    //   constructed internal bytes equal the begin-order digest above.
    //
    // Circuit shape (HDv1): output key bound at public_inputs[4],[5]; public_inputs[1]
    // (asset id) and [3] (TFR anchor) are NOT constrained in-circuit (consensus binds
    // them), hence CANON_ASSET_ID_FREE | CANON_TFR_FREE.
    //
    // MUST be re-verified against the genesis-deployed asset's registered vk_commitment
    // before mainnet. Changing this set is a consensus change. See REUSABLE_KYC.md §3, §7.
    static const std::map<uint256, CanonicalVkInfo> allowlist{
        {uint256{"45e213a031562e0c2bd1217e5b58fdca4f924052bae2d99d3063a8524ee818d8"},
         {/*circuit_id=*/"hd_v1_depth8", /*depth=*/8, /*public_input_count=*/6,
          CANON_HD_OUTPUT_BOUND | CANON_ASSET_ID_FREE | CANON_TFR_FREE}},
    };
    return allowlist;
}

bool IsCanonicalVk(const uint256& vk_hash)
{
    if (vk_hash.IsNull()) return false;
    return CanonicalVkAllowlist().count(vk_hash) != 0;
}

} // namespace assets
