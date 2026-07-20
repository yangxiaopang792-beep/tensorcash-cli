// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>

#include <assets/asset.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <serialize.h>
#include <txmempool.h>
#include <util/transaction_identifier.h>
#include <util/chaintype.h>

#include <compat/endian.h>
#include <deque>
#include <map>
#include <set>
#include <utility>

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

    void SpendCoin(const COutPoint& outpoint)
    {
        m_coins.erase(outpoint);
    }
};

void initialize_asset_mempool()
{
    SelectParams(ChainType::REGTEST);
}

} // namespace

// Fuzz mempool acceptance of asset transactions
FUZZ_TARGET(asset_mempool_acceptance, .init = initialize_asset_mempool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());


    struct MempoolAssetState {
        std::set<uint256> registered_assets;
        std::map<uint256, COutPoint> asset_icus;
        std::map<COutPoint, std::pair<uint256, uint64_t>> asset_utxos;
    } state;

    FuzzCoinsView base_view;

    const size_t num_assets = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 5);
    for (size_t i = 0; i < num_assets; ++i) {
        const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
        state.registered_assets.insert(asset_id);
        COutPoint icu;
        icu.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
        icu.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

        CTxOut icu_out;
        icu_out.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
        icu_out.scriptPubKey = CScript() << OP_TRUE;
        state.asset_icus[asset_id] = icu;
        Coin icu_coin(std::move(icu_out), /*height=*/1, /*coinbase=*/false);
        base_view.StoreCoin(icu, icu_coin);
    }

    const size_t num_txs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 20);

    for (size_t tx_idx = 0; tx_idx < num_txs; ++tx_idx) {
        CMutableTransaction mtx;
        mtx.version = 2;

        std::map<uint256, int64_t> deltas;
        size_t total_ext_size = 0;

        const size_t num_inputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 5);
        for (size_t i = 0; i < num_inputs; ++i) {
            CTxIn in;
            if (!state.asset_utxos.empty() && fuzzed_data_provider.ConsumeBool()) {
                auto it = state.asset_utxos.begin();
                std::advance(it, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, state.asset_utxos.size() - 1));
                in.prevout = it->first;
                deltas[it->second.first] -= static_cast<int64_t>(it->second.second);
            } else {
                in.prevout.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
                in.prevout.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

                CTxOut prev_out;
                prev_out.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
                prev_out.scriptPubKey = ConsumeScript(fuzzed_data_provider);
                if (fuzzed_data_provider.ConsumeBool()) {
                    const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                    const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
                    std::vector<unsigned char> tlv;
                    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
                    tlv.push_back(40);
                    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                    unsigned char amount_bytes[8];
                    WriteLE64(amount_bytes, amount);
                    tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                    prev_out.vExt = tlv;
                    deltas[asset_id] -= static_cast<int64_t>(amount);
                }
                Coin coin(std::move(prev_out), /*height=*/1, /*coinbase=*/false);
                base_view.StoreCoin(in.prevout, coin);
            }
            in.scriptSig = ConsumeScript(fuzzed_data_provider);
            mtx.vin.push_back(std::move(in));
        }

        const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);
        for (size_t i = 0; i < num_outputs; ++i) {
            CTxOut out;
            out.nValue = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(1, 1000000);
            out.scriptPubKey = ConsumeScript(fuzzed_data_provider);

            if (fuzzed_data_provider.ConsumeBool()) {
                const uint8_t op_type = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 2);
                if (op_type == 0 && !state.registered_assets.empty()) {
                    auto it = state.registered_assets.begin();
                    std::advance(it, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, state.registered_assets.size() - 1));
                    const uint256 asset_id = *it;
                    const uint64_t amount = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(1, 10000000);
                    std::vector<unsigned char> tlv;
                    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
                    tlv.push_back(40);
                    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                    unsigned char amount_bytes[8];
                    WriteLE64(amount_bytes, amount);
                    tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                    out.vExt = tlv;
                    deltas[asset_id] += static_cast<int64_t>(amount);
                } else if (op_type == 1) {
                    const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                    const uint32_t policy = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                    const uint16_t families = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
                    // Build v1 IssuerReg TLV (221-232 bytes)
                    out.vExt = test_util::BuildV1IssuerReg(asset_id, policy, families);
                } else {
                    out.vExt = ConsumeRandomLengthByteVector(fuzzed_data_provider, 100);
                }
                total_ext_size += out.vExt.size();
            }

            mtx.vout.push_back(std::move(out));
        }

        CTransaction tx(mtx);
        CCoinsViewCache cache(&base_view);
        TxValidationState validation_state;
        const int spend_height = 100 + fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 1000);
        CAmount txfee = 0;
        const bool consensus_ok = Consensus::CheckTxInputs(tx, validation_state, cache, spend_height, txfee);

        std::string reason;
        const CFeeRate dust_relay_fee{1000};
        const bool is_standard = IsStandardTx(tx, std::nullopt, /*permit_bare_multisig=*/true, dust_relay_fee, reason);

        (void)total_ext_size;
        (void)deltas;

        if (consensus_ok && is_standard) {
            // Remove spent coins
            for (const auto& in : tx.vin) {
                base_view.SpendCoin(in.prevout);
                state.asset_utxos.erase(in.prevout);
            }
            // Add produced outputs so future transactions can spend them
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                const CTxOut& out = tx.vout[i];
                const COutPoint outpoint(tx.GetHash(), i);
                Coin produced(CTxOut(out), /*height=*/1, /*coinbase=*/false);
                base_view.StoreCoin(outpoint, produced);
                if (!out.vExt.empty()) {
                    if (const auto tag = assets::ParseAssetTag(out.vExt)) {
                        state.asset_utxos[outpoint] = {tag->id, tag->amount};
                    }
                }
            }
        }
    }
}

// Fuzz mempool eviction with asset transactions
FUZZ_TARGET(asset_mempool_eviction, .init = initialize_asset_mempool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    struct MempoolSim {
        std::deque<CTransaction> txs;
        size_t total_size = 0;
        const size_t max_size = 1000000;
        std::map<uint256, size_t> tx_sizes;
    } mempool;

    while (fuzzed_data_provider.remaining_bytes() > 0) {
        CMutableTransaction mtx;
        mtx.version = 2;

        const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 20);
        for (size_t i = 0; i < num_outputs; ++i) {
            CTxOut out;
            out.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
            out.scriptPubKey = ConsumeScript(fuzzed_data_provider);
            if (fuzzed_data_provider.ConsumeBool()) {
                std::vector<unsigned char> tlv;
                tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
                tlv.push_back(40);
                const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
                tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                unsigned char amount_bytes[8];
                WriteLE64(amount_bytes, fuzzed_data_provider.ConsumeIntegral<uint64_t>());
                tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                out.vExt = tlv;
            }
            mtx.vout.push_back(out);
        }

        CTransaction tx(mtx);
        DataStream ss;
        ss << TX_WITH_WITNESS(tx);
        const size_t tx_size = ss.size();

        if (mempool.total_size + tx_size > mempool.max_size && !mempool.txs.empty()) {
            const CTransaction& evicted = mempool.txs.front();
            mempool.total_size -= mempool.tx_sizes[evicted.GetHash()];
            mempool.tx_sizes.erase(evicted.GetHash());
            mempool.txs.pop_front();
        }

        mempool.txs.push_back(tx);
        mempool.total_size += tx_size;
        mempool.tx_sizes[tx.GetHash()] = tx_size;
        assert(mempool.total_size <= mempool.max_size || mempool.txs.size() == 1);
    }
}

// Fuzz RBF with asset transactions
FUZZ_TARGET(asset_mempool_rbf, .init = initialize_asset_mempool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CMutableTransaction orig_tx;
    orig_tx.version = 2;

    CTxIn in;
    in.prevout.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
    in.prevout.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    in.nSequence = 0xfffffffd;
    orig_tx.vin.push_back(in);

    const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
    const uint64_t asset_amount = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(1000, 1000000);

    CTxOut out;
    out.nValue = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(10000, 100000);
    out.scriptPubKey = ConsumeScript(fuzzed_data_provider);
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(40);
    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
    unsigned char amount_bytes[8];
    WriteLE64(amount_bytes, asset_amount);
    tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
    out.vExt = tlv;
    orig_tx.vout.push_back(out);

    CMutableTransaction replace_tx = orig_tx;

    switch (fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
    case 0:
        if (!replace_tx.vout.empty()) {
            replace_tx.vout[0].nValue = std::max<CAmount>(0, replace_tx.vout[0].nValue - 1000);
        }
        break;
    case 1:
        if (!replace_tx.vout.empty() && !replace_tx.vout[0].vExt.empty()) {
            const uint64_t new_amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
            unsigned char new_bytes[8];
            WriteLE64(new_bytes, new_amount);
            std::vector<unsigned char> new_tlv;
            new_tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
            new_tlv.push_back(40);
            new_tlv.insert(new_tlv.end(), asset_id.begin(), asset_id.end());
            new_tlv.insert(new_tlv.end(), new_bytes, new_bytes + 8);
            replace_tx.vout[0].vExt = new_tlv;
        }
        break;
    case 2:
        if (!replace_tx.vout.empty()) replace_tx.vout[0].vExt.clear();
        break;
    case 3:
    default: {
        CTxOut new_out;
        new_out.nValue = 5000;
        new_out.scriptPubKey = ConsumeScript(fuzzed_data_provider);
        const uint256 new_asset = ConsumeUInt256(fuzzed_data_provider);
        std::vector<unsigned char> new_tlv;
        new_tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
        new_tlv.push_back(40);
        new_tlv.insert(new_tlv.end(), new_asset.begin(), new_asset.end());
        unsigned char new_amount_bytes[8];
        WriteLE64(new_amount_bytes, static_cast<uint64_t>(500000));
        new_tlv.insert(new_tlv.end(), new_amount_bytes, new_amount_bytes + 8);
        new_out.vExt = new_tlv;
        replace_tx.vout.push_back(new_out);
        break;
    }
    }

    const auto calculate_deltas = [](const CTransaction& tx) {
        std::map<uint256, int64_t> deltas;
        for (const auto& out : tx.vout) {
            if (const auto tag = assets::ParseAssetTag(out.vExt)) {
                deltas[tag->id] += static_cast<int64_t>(tag->amount);
            }
        }
        return deltas;
    };

    const CTransaction orig(orig_tx);
    const CTransaction replacement(replace_tx);
    const bool rbf_valid = (calculate_deltas(orig) == calculate_deltas(replacement));
    (void)rbf_valid;
}
