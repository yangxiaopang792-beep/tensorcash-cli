// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/icu_acceptance_index.h>

#include <assets/icu_acceptance_record.h>
#include <common/args.h>
#include <dbwrapper.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>

constexpr uint8_t DB_ICU_ACCEPTANCE{'a'};

std::unique_ptr<IcuAcceptanceIndex> g_icu_acceptance_index;

namespace {
/// DB key: asset_id || height(BE) || txid || vout(BE). Big-endian ints make a prefix seek on asset_id
/// yield records in ascending (height, txid, vout) order.
struct DBAssetKey {
    uint256 asset_id;
    int height{0};
    uint256 txid;
    uint32_t vout{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << asset_id;
        ser_writedata32be(s, static_cast<uint32_t>(height));
        s << txid;
        ser_writedata32be(s, vout);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> asset_id;
        height = static_cast<int>(ser_readdata32be(s));
        s >> txid;
        vout = ser_readdata32be(s);
    }
};
} // namespace

/** Access to the ICU acceptance index database (indexes/icuacceptance/) */
class IcuAcceptanceIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false)
        : BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "icuacceptance", n_cache_size, f_memory, f_wipe)
    {}

    [[nodiscard]] bool WriteRecords(const std::vector<DBAssetKey>& keys)
    {
        CDBBatch batch(*this);
        for (const auto& k : keys) batch.Write(std::make_pair(DB_ICU_ACCEPTANCE, k), uint8_t{1});
        return WriteBatch(batch);
    }

    bool FindByAsset(const uint256& asset_id, std::vector<IcuAcceptanceLoc>& out)
    {
        std::unique_ptr<CDBIterator> it(NewIterator());
        it->Seek(std::make_pair(DB_ICU_ACCEPTANCE, DBAssetKey{asset_id, 0, uint256(), 0}));
        for (; it->Valid(); it->Next()) {
            std::pair<uint8_t, DBAssetKey> key;
            if (!it->GetKey(key) || key.first != DB_ICU_ACCEPTANCE) break;
            if (key.second.asset_id != asset_id) break;  // moved past this asset's range
            out.push_back({key.second.height, key.second.txid, key.second.vout, key.second.asset_id});
        }
        return true;
    }
};

IcuAcceptanceIndex::IcuAcceptanceIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "icuacceptanceindex"),
      m_db(std::make_unique<IcuAcceptanceIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

IcuAcceptanceIndex::~IcuAcceptanceIndex() = default;

bool IcuAcceptanceIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    if (!block.data) return true;
    std::vector<DBAssetKey> keys;
    for (const auto& tx : block.data->vtx) {
        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            const auto& out = tx->vout[n];
            if (out.vExt.empty()) continue;
            if (auto rec = assets::ParseIcuAcceptanceTLV(out.vExt)) {
                keys.push_back(DBAssetKey{rec->asset_id, block.height, tx->GetHash(), n});
            }
        }
    }
    if (keys.empty()) return true;
    return m_db->WriteRecords(keys);
}

BaseIndex::DB& IcuAcceptanceIndex::GetDB() const { return *m_db; }

bool IcuAcceptanceIndex::FindByAsset(const uint256& asset_id, std::vector<IcuAcceptanceLoc>& out) const
{
    return m_db->FindByAsset(asset_id, out);
}
