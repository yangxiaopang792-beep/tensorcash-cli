// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>

#include <chainparams.h>
#include <assets/asset.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <util/transaction_identifier.h>
#include <util/chaintype.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

struct FuzzCoinsView final : public CCoinsView {
    std::map<COutPoint, Coin> m_coins;

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override
    {
        const auto it = m_coins.find(outpoint);
        if (it == m_coins.end()) return std::nullopt;
        return it->second;
    }

    bool HaveCoin(const COutPoint& outpoint) const override
    {
        return m_coins.find(outpoint) != m_coins.end();
    }

    void StoreCoin(const COutPoint& outpoint, const Coin& coin)
    {
        m_coins[outpoint] = coin;
    }
};

void initialize_asset_transaction()
{
    SelectParams(ChainType::REGTEST);
}

} // namespace

// Fuzz asset transaction validation logic
FUZZ_TARGET(asset_transaction_validation, .init = initialize_asset_transaction)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());


    CMutableTransaction mtx;
    mtx.version = 2;

    std::map<uint256, int64_t> asset_deltas;
    std::set<uint256> touched_assets;

    FuzzCoinsView base_view;

    const size_t num_inputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 5);
    for (size_t i = 0; i < num_inputs; ++i) {
        CTxIn input;
        input.prevout.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
        input.prevout.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        input.scriptSig = ConsumeScript(fuzzed_data_provider);

        // Build the coin being spent and stash in the view
        CTxOut prev_out;
        prev_out.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
        prev_out.scriptPubKey = ConsumeScript(fuzzed_data_provider);
        if (fuzzed_data_provider.ConsumeBool()) {
            // Attach an AssetTag to the prevout
            const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
            const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
            const uint32_t flags = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

            std::vector<unsigned char> tlv;
            tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
            tlv.push_back(44);
            tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
            unsigned char amount_bytes[8];
            WriteLE64(amount_bytes, amount);
            tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
            unsigned char flag_bytes[4];
            WriteLE32(flag_bytes, flags);
            tlv.insert(tlv.end(), flag_bytes, flag_bytes + 4);
            prev_out.vExt = tlv;
            asset_deltas[asset_id] -= static_cast<int64_t>(amount);
            touched_assets.insert(asset_id);
        }
        Coin coin(std::move(prev_out), /*height=*/1 + fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 100), /*coinbase=*/false);
        base_view.StoreCoin(input.prevout, coin);

        mtx.vin.push_back(std::move(input));
    }

    const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < num_outputs; ++i) {
        CTxOut output;
        output.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
        output.scriptPubKey = ConsumeScript(fuzzed_data_provider);

        if (fuzzed_data_provider.ConsumeBool()) {
            const uint8_t tlv_type = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 2);
            if (tlv_type == 0) {
                const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

                std::vector<unsigned char> tlv;
                tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
                tlv.push_back(40);
                tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                unsigned char amount_bytes[8];
                WriteLE64(amount_bytes, amount);
                tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                output.vExt = tlv;
                asset_deltas[asset_id] += static_cast<int64_t>(amount);
                touched_assets.insert(asset_id);
            } else if (tlv_type == 1) {
                const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                const uint32_t policy_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                const uint16_t allowed_families = fuzzed_data_provider.ConsumeIntegral<uint16_t>();

                // Build v1 IssuerReg TLV (221-232 bytes)
                output.vExt = test_util::BuildV1IssuerReg(asset_id, policy_bits, allowed_families);
                touched_assets.insert(asset_id);
            } else {
                output.vExt = ConsumeRandomLengthByteVector(fuzzed_data_provider, 100);
            }
        }

        mtx.vout.push_back(std::move(output));
    }

    // Exercise serialization and hash paths
    CTransaction tx(mtx);
    (void)tx.GetHash();
    (void)tx.GetWitnessHash();

    // Run consensus input checks over the constructed state.
    CCoinsViewCache cache(&base_view);
    TxValidationState state;
    const int spend_height = 100 + fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 1000);
    CAmount txfee = 0;
    (void)Consensus::CheckTxInputs(tx, state, cache, spend_height, txfee);

    // Exercise standardness logic for the same transaction.
    std::string reason;
    const CFeeRate dust_relay_fee{1000};
    IsStandardTx(tx, std::nullopt, /*permit_bare_multisig=*/true, dust_relay_fee, reason);
}

// Fuzz asset delta computation
FUZZ_TARGET(asset_delta_computation, .init = initialize_asset_transaction)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::vector<CTransaction> txs;
    std::map<uint256, int64_t> cumulative_deltas;

    const size_t num_txs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);

    for (size_t tx_idx = 0; tx_idx < num_txs; ++tx_idx) {
        CMutableTransaction mtx;
        mtx.version = 2;

        const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 5);
        for (size_t i = 0; i < num_outputs; ++i) {
            CTxOut out;
            out.nValue = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(1, 1000000);
            out.scriptPubKey = CScript() << OP_TRUE;
            if (fuzzed_data_provider.ConsumeBool()) {
                const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                const uint64_t amount = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(1, 1000000);

                std::vector<unsigned char> tlv;
                tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
                tlv.push_back(40);
                tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                unsigned char amount_bytes[8];
                WriteLE64(amount_bytes, amount);
                tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                out.vExt = tlv;
                cumulative_deltas[asset_id] += static_cast<int64_t>(amount);
            }
            mtx.vout.push_back(out);
        }

        if (tx_idx > 0 && !txs.empty() && fuzzed_data_provider.ConsumeBool()) {
            const CTransaction& prev_tx = txs[fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, txs.size() - 1)];
            if (!prev_tx.vout.empty()) {
                CTxIn in;
                in.prevout.hash = prev_tx.GetHash();
                in.prevout.n = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, prev_tx.vout.size() - 1);
                mtx.vin.push_back(in);

                const CTxOut& spent_out = prev_tx.vout[in.prevout.n];
                if (!spent_out.vExt.empty()) {
                    if (const auto tag = assets::ParseAssetTag(spent_out.vExt)) {
                        cumulative_deltas[tag->id] -= static_cast<int64_t>(tag->amount);
                    }
                }
            }
        }

        txs.emplace_back(mtx);
    }

    // Feed the resulting transactions through serialization to ensure
    // the constructed asset deltas do not trigger undefined behaviour.
    for (const auto& tx : txs) {
        DataStream ss;
        ss << TX_WITH_WITNESS(tx);
    }
}
