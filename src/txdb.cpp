// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <coins.h>
#include <coins_asset_delta.h>
#include <dbwrapper.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/vector.h>

#include <cassert>
#include <cstdlib>
#include <iterator>
#include <utility>

static constexpr uint8_t DB_COIN{'C'};
static constexpr uint8_t DB_BEST_BLOCK{'B'};
static constexpr uint8_t DB_HEAD_BLOCKS{'H'};
// Keys used in previous version that might still be found in the DB:
static constexpr uint8_t DB_COINS{'c'};

// Asset registry keys (defined here so CCoinsViewDB::BatchWrite can commit the
// asset delta and DB_ASSET_BEST_BLOCK in the same final batch as the coins).
static const uint8_t DB_ASSET_REG = 'R';
static const uint8_t DB_ASSET_TICK = 'T';
static const uint8_t DB_ASSET_VK  = 'Z';
static const uint8_t DB_ASSET_ICU = 'I';
static const uint8_t DB_ASSET_SCALAR = 'S';       // per-epoch scalar publication (asset_id,feed_id,epoch)
static const uint8_t DB_ASSET_SCALAR_HEAD = 's';  // scalar feed head (asset_id,feed_id) -> last_epoch
static const uint8_t DB_ASSET_BEST_BLOCK = 'A';
static const uint8_t DB_ASSET_HEAD_BLOCKS = 'a';

bool CCoinsViewDB::NeedsUpgrade()
{
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    // DB_COINS was deprecated in v0.15.0, commit
    // 1088b02f0ccd7358d2b7076bb9e122d59d502d02
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));
    return cursor->Valid();
}

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};

} // namespace

CCoinsViewDB::CCoinsViewDB(DBParams db_params, CoinsViewOptions options) :
    m_db_params{std::move(db_params)},
    m_options{std::move(options)},
    m_db{std::make_unique<CDBWrapper>(m_db_params)} { }

void CCoinsViewDB::ResizeCache(size_t new_cache_size)
{
    // We can't do this operation with an in-memory DB since we'll lose all the coins upon
    // reset.
    if (!m_db_params.memory_only) {
        // Have to do a reset first to get the original `m_db` state to release its
        // filesystem lock.
        m_db.reset();
        m_db_params.cache_bytes = new_cache_size;
        m_db_params.wipe_data = false;
        m_db = std::make_unique<CDBWrapper>(m_db_params);
    }
}

std::optional<Coin> CCoinsViewDB::GetCoin(const COutPoint& outpoint) const
{
    if (Coin coin; m_db->Read(CoinEntry(&outpoint), coin)) return coin;
    return std::nullopt;
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return m_db->Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!m_db->Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!m_db->Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) {
    CDBBatch batch(*m_db);
    size_t count = 0;
    size_t changed = 0;
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != hashBlock) {
                LogPrintLevel(BCLog::COINDB, BCLog::Level::Error, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart bitcoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));

    for (auto it{cursor.Begin()}; it != cursor.End();) {
        if (it->second.IsDirty()) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent()) {
                batch.Erase(entry);
            } else {
                batch.Write(entry, it->second.coin);
            }

            changed++;
        }
        count++;
        it = cursor.NextAndMaybeErase(*it);
        if (batch.ApproximateSize() > m_options.batch_write_bytes) {
            LogDebug(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.ApproximateSize() * (1.0 / 1048576.0));

            m_db->WriteBatch(batch);
            batch.Clear();
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    // Commit any staged asset-registry delta in this SAME final batch — never in
    // the partial coin batches above — so the asset registry advances atomically
    // with the final best-block commit (DB_BEST_BLOCK). (The earlier partial coin
    // batches are written separately, as in stock chainstate.) DB_ASSET_BEST_BLOCK
    // is advanced to hashBlock on every flush so it always tracks the UTXO best
    // block; no separate asset progress marker is needed because the delta and the
    // best-block markers land together in this one WriteBatch.
    if (const CAssetRegistryDelta* assets = cursor.AssetDelta()) {
        for (const auto& [aid, op] : assets->policy) {
            if (op.erased) EraseAssetPolicy(aid, batch);
            else WriteAssetPolicy(aid, op.value, batch);
        }
        for (const auto& [ticker, op] : assets->ticker) {
            if (op.erased) EraseTickerBinding(ticker, batch);
            else WriteTickerBinding(ticker, op.value, batch);
        }
        for (const auto& [vk_hash, op] : assets->vk) {
            if (op.erased) EraseZkVerifyingKey(vk_hash, batch);
            else WriteZkVerifyingKey(vk_hash, op.value, batch);
        }
        for (const auto& [key, op] : assets->icu) {
            if (op.erased) EraseIcuPayload(key.asset_id, key.ctxt_commit, batch);
            else WriteIcuPayload(key.asset_id, key.ctxt_commit, op.value, batch);
        }
        for (const auto& [key, op] : assets->scalar) {
            if (op.erased) EraseAssetScalar(key.asset_id, key.feed_id, key.epoch, batch);
            else WriteAssetScalar(key.asset_id, key.feed_id, key.epoch, op.value, batch);
        }
        for (const auto& [key, op] : assets->scalar_head) {
            if (op.erased) EraseAssetScalarHead(key.asset_id, key.feed_id, batch);
            else WriteAssetScalarHead(key.asset_id, key.feed_id, op.value, batch);
        }
    }
    batch.Write(DB_ASSET_BEST_BLOCK, hashBlock);

    LogDebug(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.ApproximateSize() * (1.0 / 1048576.0));
    bool ret = m_db->WriteBatch(batch);
    LogDebug(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize(DB_COIN, uint8_t(DB_COIN + 1));
}

bool CCoinsViewDB::ReadAssetPolicy(const uint256& aid, AssetRegistryEntry& out) const
{
    return m_db->Read(std::make_pair(DB_ASSET_REG, aid), out);
}

uint256 CCoinsViewDB::GetAssetRegistryBestBlock() const
{
    uint256 hash_best;
    if (!m_db->Read(DB_ASSET_BEST_BLOCK, hash_best)) return uint256();
    return hash_best;
}

std::vector<uint256> CCoinsViewDB::GetAssetRegistryHeadBlocks() const
{
    std::vector<uint256> heads;
    if (!m_db->Read(DB_ASSET_HEAD_BLOCKS, heads)) return {};
    return heads;
}

std::vector<uint256> CCoinsViewDB::GetAllRegisteredAssets() const
{
    std::vector<uint256> ids;
    std::unique_ptr<CDBIterator> it(const_cast<CDBWrapper&>(*m_db).NewIterator());
    // DB_ASSET_REG entries are keyed (DB_ASSET_REG, asset_id) and sorted
    // contiguously; iterate from the prefix start until the prefix byte changes.
    for (it->Seek(std::make_pair(DB_ASSET_REG, uint256())); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != DB_ASSET_REG) break;
        ids.push_back(key.second);
    }
    return ids;
}

bool CCoinsViewDB::WriteAssetPolicy(const uint256& aid, const AssetRegistryEntry& in, CDBBatch& batch)
{
    batch.Write(std::make_pair(DB_ASSET_REG, aid), in);
    return true;
}

bool CCoinsViewDB::EraseAssetPolicy(const uint256& aid, CDBBatch& batch)
{
    batch.Erase(std::make_pair(DB_ASSET_REG, aid));
    return true;
}

bool CCoinsViewDB::WriteAssetPolicy(const uint256& aid, const AssetRegistryEntry& in)
{
    CDBBatch batch(*m_db);
    WriteAssetPolicy(aid, in, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::EraseAssetPolicy(const uint256& aid)
{
    CDBBatch batch(*m_db);
    EraseAssetPolicy(aid, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::ReadTickerBinding(const std::string& ticker, uint256& out_asset) const
{
    return m_db->Read(std::make_pair(DB_ASSET_TICK, ticker), out_asset);
}

bool CCoinsViewDB::WriteTickerBinding(const std::string& ticker, const uint256& asset, CDBBatch& batch)
{
    batch.Write(std::make_pair(DB_ASSET_TICK, ticker), asset);
    return true;
}

bool CCoinsViewDB::EraseTickerBinding(const std::string& ticker, CDBBatch& batch)
{
    batch.Erase(std::make_pair(DB_ASSET_TICK, ticker));
    return true;
}

bool CCoinsViewDB::WriteTickerBinding(const std::string& ticker, const uint256& asset)
{
    CDBBatch batch(*m_db);
    WriteTickerBinding(ticker, asset, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::EraseTickerBinding(const std::string& ticker)
{
    CDBBatch batch(*m_db);
    EraseTickerBinding(ticker, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::ReadZkVerifyingKey(const uint256& vk_hash, std::vector<unsigned char>& out) const
{
    return m_db->Read(std::make_pair(DB_ASSET_VK, vk_hash), out);
}

bool CCoinsViewDB::WriteZkVerifyingKey(const uint256& vk_hash, const std::vector<unsigned char>& bytes, CDBBatch& batch)
{
    batch.Write(std::make_pair(DB_ASSET_VK, vk_hash), bytes);
    return true;
}

bool CCoinsViewDB::EraseZkVerifyingKey(const uint256& vk_hash, CDBBatch& batch)
{
    batch.Erase(std::make_pair(DB_ASSET_VK, vk_hash));
    return true;
}

bool CCoinsViewDB::WriteZkVerifyingKey(const uint256& vk_hash, const std::vector<unsigned char>& bytes)
{
    CDBBatch batch(*m_db);
    WriteZkVerifyingKey(vk_hash, bytes, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::EraseZkVerifyingKey(const uint256& vk_hash)
{
    CDBBatch batch(*m_db);
    EraseZkVerifyingKey(vk_hash, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::ReadIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, assets::IcuStorageEntry& out) const
{
    return m_db->Read(std::make_pair(DB_ASSET_ICU, std::make_pair(asset_id, icu_ctxt_commit)), out);
}

bool CCoinsViewDB::WriteIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, const assets::IcuStorageEntry& entry, CDBBatch& batch)
{
    batch.Write(std::make_pair(DB_ASSET_ICU, std::make_pair(asset_id, icu_ctxt_commit)), entry);
    return true;
}

bool CCoinsViewDB::EraseIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, CDBBatch& batch)
{
    batch.Erase(std::make_pair(DB_ASSET_ICU, std::make_pair(asset_id, icu_ctxt_commit)));
    return true;
}

bool CCoinsViewDB::WriteIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, const assets::IcuStorageEntry& entry)
{
    CDBBatch batch(*m_db);
    WriteIcuPayload(asset_id, icu_ctxt_commit, entry, batch);
    return m_db->WriteBatch(batch);
}

bool CCoinsViewDB::EraseIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit)
{
    CDBBatch batch(*m_db);
    EraseIcuPayload(asset_id, icu_ctxt_commit, batch);
    return m_db->WriteBatch(batch);
}

// --- Scalar feed (CFD_GENERALISATION.md §3.2) ---
// Per-epoch key: (DB_ASSET_SCALAR, (asset_id, (feed_id, epoch))) -> ScalarRecord.
// Head key:      (DB_ASSET_SCALAR_HEAD, (asset_id, feed_id)) -> last_epoch (uint64).
// Both are O(1) point lookups, written only via the atomic BatchWrite path below.

bool CCoinsViewDB::ReadAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, ScalarRecord& out) const
{
    return m_db->Read(std::make_pair(DB_ASSET_SCALAR, std::make_pair(asset_id, std::make_pair(feed_id, epoch))), out);
}

bool CCoinsViewDB::WriteAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, const ScalarRecord& rec, CDBBatch& batch)
{
    batch.Write(std::make_pair(DB_ASSET_SCALAR, std::make_pair(asset_id, std::make_pair(feed_id, epoch))), rec);
    return true;
}

bool CCoinsViewDB::EraseAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, CDBBatch& batch)
{
    batch.Erase(std::make_pair(DB_ASSET_SCALAR, std::make_pair(asset_id, std::make_pair(feed_id, epoch))));
    return true;
}

bool CCoinsViewDB::ReadAssetScalarHead(const uint256& asset_id, uint32_t feed_id, uint64_t& out_last_epoch) const
{
    return m_db->Read(std::make_pair(DB_ASSET_SCALAR_HEAD, std::make_pair(asset_id, feed_id)), out_last_epoch);
}

bool CCoinsViewDB::WriteAssetScalarHead(const uint256& asset_id, uint32_t feed_id, uint64_t last_epoch, CDBBatch& batch)
{
    batch.Write(std::make_pair(DB_ASSET_SCALAR_HEAD, std::make_pair(asset_id, feed_id)), last_epoch);
    return true;
}

bool CCoinsViewDB::EraseAssetScalarHead(const uint256& asset_id, uint32_t feed_id, CDBBatch& batch)
{
    batch.Erase(std::make_pair(DB_ASSET_SCALAR_HEAD, std::make_pair(asset_id, feed_id)));
    return true;
}

std::vector<std::pair<uint32_t, uint64_t>> CCoinsViewDB::GetAssetScalarFeeds(const uint256& asset_id) const
{
    std::vector<std::pair<uint32_t, uint64_t>> out;
    std::unique_ptr<CDBIterator> it(const_cast<CDBWrapper&>(*m_db).NewIterator());
    // Head keys are (DB_ASSET_SCALAR_HEAD, (asset_id, feed_id)); all feeds for one asset
    // share the (prefix, asset_id) head and are contiguous. Stop when either changes.
    for (it->Seek(std::make_pair(DB_ASSET_SCALAR_HEAD, std::make_pair(asset_id, uint32_t{0})));
         it->Valid(); it->Next()) {
        std::pair<uint8_t, std::pair<uint256, uint32_t>> key;
        if (!it->GetKey(key) || key.first != DB_ASSET_SCALAR_HEAD || key.second.first != asset_id) break;
        uint64_t last_epoch = 0;
        if (it->GetValue(last_epoch)) out.emplace_back(key.second.second, last_epoch);
    }
    return out;
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    // Prefer using CCoinsViewDB::Cursor() since we want to perform some
    // cache warmup on instantiation.
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256&hashBlockIn):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;
};

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    auto i = std::make_unique<CCoinsViewDBCursor>(
        const_cast<CDBWrapper&>(*m_db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}
