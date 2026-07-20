// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>

#include <assets/asset.h>
#include <serialize.h>
#include <streams.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace {

std::vector<unsigned char> MakeAssetTagTLV(FuzzedDataProvider& fuzzed_data_provider)
{
    const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
    const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    const bool include_flags = fuzzed_data_provider.ConsumeBool();
    const uint32_t flags = include_flags ? fuzzed_data_provider.ConsumeIntegral<uint32_t>() : 0;

    std::vector<unsigned char> payload;
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_bytes[8];
    WriteLE64(amount_bytes, amount);
    payload.insert(payload.end(), amount_bytes, amount_bytes + 8);
    if (include_flags) {
        unsigned char flag_bytes[4];
        WriteLE32(flag_bytes, flags);
        payload.insert(payload.end(), flag_bytes, flag_bytes + 4);
    }

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    // Payload is small, so a single-byte CompactSize representation suffices.
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::vector<unsigned char> MakeIssuerRegTLV(FuzzedDataProvider& fuzzed_data_provider)
{
    const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
    const uint32_t policy_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const bool include_allowed_mask = fuzzed_data_provider.ConsumeBool();
    const bool include_unlock = fuzzed_data_provider.ConsumeBool();
    const bool include_ticker = fuzzed_data_provider.ConsumeBool();
    const bool include_decimals = include_ticker && fuzzed_data_provider.ConsumeBool();

    std::vector<unsigned char> payload;
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char policy_bytes[4];
    WriteLE32(policy_bytes, policy_bits);
    payload.insert(payload.end(), policy_bytes, policy_bytes + 4);

    if (include_allowed_mask) {
        const uint16_t mask = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
        payload.push_back(mask & 0xffu);
        payload.push_back((mask >> 8) & 0xffu);
    }

    if (include_unlock) {
        const uint64_t unlock = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
        unsigned char unlock_bytes[8];
        WriteLE64(unlock_bytes, unlock);
        payload.insert(payload.end(), unlock_bytes, unlock_bytes + 8);
    }

    if (include_ticker) {
        const uint8_t len = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(3, 11);
        payload.push_back(len);
        for (uint8_t i = 0; i < len; ++i) {
            char c;
            if (i == 0) {
                c = static_cast<char>(fuzzed_data_provider.ConsumeIntegralInRange<int>('A', 'Z'));
            } else {
                const bool digit = fuzzed_data_provider.ConsumeBool();
                if (digit) {
                    c = static_cast<char>(fuzzed_data_provider.ConsumeIntegralInRange<int>('0', '9'));
                } else {
                    const bool lower = fuzzed_data_provider.ConsumeBool();
                    c = static_cast<char>(fuzzed_data_provider.ConsumeIntegralInRange<int>('A', 'Z'));
                    if (lower) c = static_cast<char>(c - 'A' + 'a');
                }
            }
            payload.push_back(static_cast<unsigned char>(std::toupper(c)));
        }
        if (include_decimals) {
            payload.push_back(fuzzed_data_provider.ConsumeIntegral<uint8_t>());
        }
    }

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ISSUER_REG));
    // Payload sizes stay below CompactSize single-byte threshold.
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

} // namespace

// Fuzz the TLV parser for AssetTag and IssuerReg
FUZZ_TARGET(asset_tlv_parser)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    std::vector<unsigned char> tlv_data;
    const uint8_t choice = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
    if ((choice % 3) == 0 && fuzzed_data_provider.remaining_bytes() > 0) {
        tlv_data = MakeAssetTagTLV(fuzzed_data_provider);
    } else if ((choice % 3) == 1 && fuzzed_data_provider.remaining_bytes() > 0) {
        tlv_data = MakeIssuerRegTLV(fuzzed_data_provider);
    } else {
        tlv_data = ConsumeRandomLengthByteVector(fuzzed_data_provider);
    }

    // Test AssetTag parsing
    {
        auto result = assets::ParseAssetTag(tlv_data);
        if (result.has_value()) {
            const auto& tag = result.value();
            assert(tag.amount <= std::numeric_limits<uint64_t>::max());
            assert(tag.flags <= std::numeric_limits<uint32_t>::max());
            assert(tag.id.size() == 32);
        }
    }

    // Test IssuerReg parsing
    {
        auto result = assets::ParseIssuerReg(tlv_data);
        if (result.has_value()) {
            const auto& reg = result.value();
            assert(reg.policy_bits <= std::numeric_limits<uint32_t>::max());
            assert(reg.allowed_spk_families <= std::numeric_limits<uint16_t>::max());
            assert(reg.asset_id.size() == 32);
            // v1: ticker sentinel is empty string; any non-empty parsed ticker must satisfy the
            // shared grammar — a bare root, or a one-hop child ROOT.SUFFIX up to 23 bytes
            // (ICU_CHILD.md §5.1). (The old <=11 invariant predated sponsored children.)
            if (!reg.ticker.empty()) {
                assert(assets::IsTickerValidForIssuerReg(reg.ticker));
            }
        }
    }

    if (!tlv_data.empty()) {
        // Truncations should not crash the parser
        for (size_t i = 0; i < tlv_data.size(); ++i) {
            std::vector<unsigned char> truncated(tlv_data.begin(), tlv_data.begin() + i);
            assets::ParseAssetTag(truncated);
            assets::ParseIssuerReg(truncated);
        }

        // Append extra garbage to stress bounds
        std::vector<unsigned char> with_garbage = tlv_data;
        const std::vector<unsigned char> extra = ConsumeRandomLengthByteVector(fuzzed_data_provider);
        with_garbage.insert(with_garbage.end(), extra.begin(), extra.end());
        assets::ParseAssetTag(with_garbage);
        assets::ParseIssuerReg(with_garbage);
    }

    // Specific malformed cases
    if (fuzzed_data_provider.ConsumeBool()) {
        std::vector<unsigned char> malformed = {fuzzed_data_provider.ConsumeIntegral<uint8_t>()};
        assets::ParseAssetTag(malformed);
        assets::ParseIssuerReg(malformed);
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        std::vector<unsigned char> malformed = {
            fuzzed_data_provider.ConsumeIntegral<uint8_t>(),
            fuzzed_data_provider.ConsumeIntegral<uint8_t>()};
        assets::ParseAssetTag(malformed);
        assets::ParseIssuerReg(malformed);
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        std::vector<unsigned char> malformed = {0x01};
        malformed.insert(malformed.end(), 10, 0xFF);
        assets::ParseAssetTag(malformed);
    }
}

// Fuzz TLV serialization/deserialization round-trip
FUZZ_TARGET(asset_tlv_roundtrip)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CMutableTransaction mtx;
    mtx.version = 2;

    const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < num_outputs; ++i) {
        CTxOut out;
        out.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
        out.scriptPubKey = ConsumeScript(fuzzed_data_provider);
        if (fuzzed_data_provider.ConsumeBool()) {
            switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 2)) {
            case 0:
                out.vExt = MakeAssetTagTLV(fuzzed_data_provider);
                break;
            case 1:
                out.vExt = MakeIssuerRegTLV(fuzzed_data_provider);
                break;
            default:
                out.vExt = ConsumeRandomLengthByteVector(fuzzed_data_provider, 256);
                break;
            }
        }
        mtx.vout.push_back(out);
    }

    DataStream ss_out;
    ss_out << TX_WITH_WITNESS(mtx);

    try {
        DataStream ss_in(ss_out);
        CMutableTransaction mtx2(deserialize, TX_WITH_WITNESS, ss_in);
        assert(mtx.vout.size() == mtx2.vout.size());
        for (size_t i = 0; i < mtx.vout.size(); ++i) {
            assert(mtx.vout[i].vExt == mtx2.vout[i].vExt);
        }
    } catch (...) {
        // Deserialization failures are acceptable when random data violates bounds
    }
}
