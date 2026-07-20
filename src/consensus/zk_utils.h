// Helpers shared between consensus enforcement and tests for KYC/ZK bindings.

#ifndef BITCOIN_CONSENSUS_ZK_UTILS_H
#define BITCOIN_CONSENSUS_ZK_UTILS_H

#include <array>

#include <chainparams.h>
#include <cstdint>
#include <hash.h>
#include <span.h>
#include <uint256.h>

namespace Consensus {

inline std::array<unsigned char, 32> Uint256ToBytesBE(const uint256& value)
{
    std::array<unsigned char, 32> out{};
    const unsigned char* in = value.begin();
    for (size_t i = 0; i < 32; ++i) {
        out[31 - i] = in[i];
    }
    return out;
}

inline uint256 ComputeChainSeparator(const CChainParams& params)
{
    static const std::string kTag{"TensorCash/ZKChainSeparator"};
    CHash256 hasher;
    const uint256& genesis = params.GetConsensus().hashGenesisBlock;
    hasher.Write({genesis.begin(), 32});
    hasher.Write({reinterpret_cast<const unsigned char*>(kTag.data()), kTag.size()});
    uint256 out;
    hasher.Finalize({out.begin(), 32});
    return out;
}

inline std::array<unsigned char, 32> ComputeChainSeparatorBytes(const CChainParams& params)
{
    return Uint256ToBytesBE(ComputeChainSeparator(params));
}

inline std::array<unsigned char, 32> BuildComplianceField(uint256 root, uint32_t height)
{
    auto bytes = Uint256ToBytesBE(root);
    bytes[28] = static_cast<unsigned char>((height >> 24) & 0xFF);
    bytes[29] = static_cast<unsigned char>((height >> 16) & 0xFF);
    bytes[30] = static_cast<unsigned char>((height >> 8) & 0xFF);
    bytes[31] = static_cast<unsigned char>(height & 0xFF);
    return bytes;
}

inline uint32_t ExtractComplianceHeight(std::span<const unsigned char> element)
{
    if (element.size() != 32) return 0;
    return (static_cast<uint32_t>(element[28]) << 24) |
           (static_cast<uint32_t>(element[29]) << 16) |
           (static_cast<uint32_t>(element[30]) << 8) |
           static_cast<uint32_t>(element[31]);
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_ZK_UTILS_H
