// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_FAIRSIGN_H
#define TENSORCASH_WALLET_FAIRSIGN_H

#include <psbt.h>

#include <string_view>
#include <vector>

namespace wallet::fairsign {

inline const std::vector<unsigned char>& Identifier()
{
    static const std::vector<unsigned char> kId{'f', 's'};
    return kId;
}

inline const std::vector<unsigned char>& AdvisoryIdentifier()
{
    static const std::vector<unsigned char> kId{'x'};
    return kId;
}

inline constexpr std::string_view kGlobalPolicyKey{"policy"};
inline constexpr std::string_view kGlobalContractMetaKey{"contract_meta"};

inline constexpr std::string_view kInputNonceKey{"nonce_pub"};
inline constexpr std::string_view kInputAdaptorPointKey{"adaptor_point"};
inline constexpr std::string_view kInputAdaptorSigKey{"adaptor_sig"};
inline constexpr std::string_view kInputCommitmentKey{"commitment"};
inline constexpr std::string_view kInputMuSigPubKeysKey{"musig_pubkeys"};
inline constexpr std::string_view kInputMuSigAggNonceKey{"musig_aggnonce"};
inline constexpr std::string_view kInputMuSigPubNoncePrefix{"musig_pubnonce/"};
inline constexpr std::string_view kInputMuSigPartialPrefix{"musig_partial/"};

inline constexpr std::string_view kOutputIsChangeKey{"is_change"};
inline constexpr std::string_view kOutputAssetKey{"asset"};

} // namespace wallet::fairsign

#endif // TENSORCASH_WALLET_FAIRSIGN_H
