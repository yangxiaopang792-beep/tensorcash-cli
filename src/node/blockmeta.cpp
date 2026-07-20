// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockmeta.h>

#include <logging.h>
#include <streams.h>

namespace node {

//! Database key prefix for block metadata entries.
//! Using 'M' to distinguish from other block index prefixes.
static constexpr uint8_t DB_BLOCKMETA = 'M';

struct BlockMetaKey {
    uint8_t prefix;
    uint256 hash;

    BlockMetaKey(const uint256& h) : prefix(DB_BLOCKMETA), hash(h) {}

    SERIALIZE_METHODS(BlockMetaKey, obj)
    {
        READWRITE(obj.prefix, obj.hash);
    }
};

BlockMetaDB::BlockMetaDB(const fs::path& path,
                         size_t cache_size_bytes,
                         bool memory_only,
                         bool wipe_data)
{
    DBParams params{
        .path = path / "blockmeta",
        .cache_bytes = cache_size_bytes,
        .memory_only = memory_only,
        .wipe_data = wipe_data,
        .obfuscate = true,
    };

    LOCK(m_cs_blockmeta);
    m_db = std::make_unique<CDBWrapper>(params);
    LogDebug(BCLog::VALIDATION, "BlockMetaDB opened at %s\n", fs::PathToString(path));
}

BlockMetaDB::~BlockMetaDB()
{
    Flush();
}

void BlockMetaDB::MaybeEvictCache()
{
    AssertLockHeld(m_cs_blockmeta);
    if (m_cache.size() > MAX_CACHE_SIZE) {
        // Simple eviction: clear half the cache when it gets too big.
        // A more sophisticated LRU could be added if needed.
        auto it = m_cache.begin();
        size_t to_remove = m_cache.size() / 2;
        for (size_t i = 0; i < to_remove && it != m_cache.end(); ++i) {
            it = m_cache.erase(it);
        }
    }
}

bool BlockMetaDB::WriteFirstSeen(const uint256& block_hash, int64_t now, int32_t tip_height)
{
    LOCK(m_cs_blockmeta);

    // Check cache first
    if (m_cache.count(block_hash)) {
        return false;  // Already have metadata
    }

    // Check database
    BlockMetaKey key(block_hash);
    BlockMeta existing;
    if (m_db->Read(key, existing)) {
        // Already exists in DB, add to cache
        m_cache[block_hash] = existing;
        return false;
    }

    // Write new entry
    BlockMeta meta{
        .first_seen_ts = now,
        .first_seen_height = tip_height,
    };

    if (!m_db->Write(key, meta)) {
        LogError("BlockMetaDB: Failed to write first_seen for %s\n", block_hash.ToString());
        return false;
    }

    // Add to cache
    m_cache[block_hash] = meta;
    MaybeEvictCache();

    LogDebug(BCLog::VALIDATION, "BlockMetaDB: Recorded first_seen for %s at ts=%ld height=%d\n",
             block_hash.ToString(), now, tip_height);
    return true;
}

std::optional<BlockMeta> BlockMetaDB::Read(const uint256& block_hash) const
{
    LOCK(m_cs_blockmeta);

    // Check cache first
    auto it = m_cache.find(block_hash);
    if (it != m_cache.end()) {
        return it->second;
    }

    // Check database
    BlockMetaKey key(block_hash);
    BlockMeta meta;
    if (m_db->Read(key, meta)) {
        // Add to cache for future reads
        m_cache[block_hash] = meta;
        const_cast<BlockMetaDB*>(this)->MaybeEvictCache();
        return meta;
    }

    return std::nullopt;
}

bool BlockMetaDB::Exists(const uint256& block_hash) const
{
    LOCK(m_cs_blockmeta);

    // Check cache first
    if (m_cache.count(block_hash)) {
        return true;
    }

    // Check database
    BlockMetaKey key(block_hash);
    return m_db->Exists(key);
}

int64_t BlockMetaDB::GetFirstSeenTs(const uint256& block_hash) const
{
    auto meta = Read(block_hash);
    return meta ? meta->first_seen_ts : 0;
}

void BlockMetaDB::Flush()
{
    LOCK(m_cs_blockmeta);
    if (m_db) {
        // Force a sync to disk using an empty batch write with fSync=true.
        // This ensures all previously written metadata is durable.
        CDBBatch batch(*m_db);
        m_db->WriteBatch(batch, /*fSync=*/true);
        LogDebug(BCLog::VALIDATION, "BlockMetaDB: Flushed to disk\n");
    }
}

void BlockMetaDB::ClearCache()
{
    LOCK(m_cs_blockmeta);
    m_cache.clear();
}

size_t BlockMetaDB::PruneBefore(int32_t max_height)
{
    LOCK(m_cs_blockmeta);

    if (!m_db) return 0;

    size_t deleted = 0;
    CDBBatch batch(*m_db);

    // Iterate through all entries and delete those at or below max_height
    std::unique_ptr<CDBIterator> iter(m_db->NewIterator());

    BlockMetaKey prefix_key(uint256::ZERO);
    iter->Seek(prefix_key);

    while (iter->Valid()) {
        BlockMetaKey key(uint256::ZERO);
        if (!iter->GetKey(key)) {
            break;
        }

        // Check if this is a BlockMeta entry (has our prefix)
        if (key.prefix != DB_BLOCKMETA) {
            break;
        }

        BlockMeta meta;
        if (iter->GetValue(meta)) {
            if (meta.first_seen_height >= 0 && meta.first_seen_height <= max_height) {
                batch.Erase(key);
                // Also remove from cache
                m_cache.erase(key.hash);
                ++deleted;
            }
        }

        iter->Next();
    }

    if (deleted > 0) {
        m_db->WriteBatch(batch, /*fSync=*/true);
        LogDebug(BCLog::VALIDATION, "BlockMetaDB: Pruned %zu entries with first_seen_height <= %d\n",
                 deleted, max_height);
    }

    return deleted;
}

size_t BlockMetaDB::GetEntryCount() const
{
    LOCK(m_cs_blockmeta);

    if (!m_db) return 0;

    size_t count = 0;
    std::unique_ptr<CDBIterator> iter(m_db->NewIterator());

    BlockMetaKey prefix_key(uint256::ZERO);
    iter->Seek(prefix_key);

    while (iter->Valid()) {
        BlockMetaKey key(uint256::ZERO);
        if (!iter->GetKey(key) || key.prefix != DB_BLOCKMETA) {
            break;
        }
        ++count;
        iter->Next();
    }

    return count;
}

std::optional<fs::path> BlockMetaDB::StoragePath() const
{
    LOCK(m_cs_blockmeta);
    return m_db ? m_db->StoragePath() : std::nullopt;
}

} // namespace node
