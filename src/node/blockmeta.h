// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKMETA_H
#define BITCOIN_NODE_BLOCKMETA_H

#include <dbwrapper.h>
#include <primitives/block.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>

namespace node {

/**
 * Metadata stored per-block for reorg advisory purposes.
 * This is non-consensus data that tracks when this node first observed each block.
 */
struct BlockMeta {
    //! Unix timestamp (seconds) when this node first saw the block.
    //! Never updated after initial set. 0 means unknown (e.g., loaded from disk at startup).
    int64_t first_seen_ts{0};

    //! Height of the active tip when the block was first seen.
    //! Useful for detecting how far behind we were when we first observed this block.
    int32_t first_seen_height{-1};

    SERIALIZE_METHODS(BlockMeta, obj)
    {
        READWRITE(obj.first_seen_ts, obj.first_seen_height);
    }

    bool IsKnown() const { return first_seen_ts > 0; }
};

/**
 * Database for storing per-block metadata (first_seen_ts, etc.).
 * Uses a separate prefix in the existing block index DB to avoid new files.
 *
 * Thread safety: All public methods are thread-safe via internal locking.
 */
class BlockMetaDB
{
private:
    mutable Mutex m_cs_blockmeta;
    std::unique_ptr<CDBWrapper> m_db GUARDED_BY(m_cs_blockmeta);

    //! In-memory cache for recently accessed block metadata.
    //! Avoids repeated disk reads for hot blocks.
    mutable std::map<uint256, BlockMeta> m_cache GUARDED_BY(m_cs_blockmeta);
    static constexpr size_t MAX_CACHE_SIZE = 1000;

    void MaybeEvictCache() EXCLUSIVE_LOCKS_REQUIRED(m_cs_blockmeta);

public:
    /**
     * @param path Directory for the metadata database (typically blocks/index/).
     * @param cache_size_bytes LevelDB cache size.
     * @param memory_only If true, use in-memory database (for testing).
     * @param wipe_data If true, clear existing data on open.
     */
    explicit BlockMetaDB(const fs::path& path,
                         size_t cache_size_bytes = 2 << 20,  // 2 MiB default
                         bool memory_only = false,
                         bool wipe_data = false);

    ~BlockMetaDB();

    /**
     * Record the first-seen timestamp for a block.
     * Does nothing if metadata already exists for this block hash.
     *
     * @param block_hash Hash of the block.
     * @param now Current Unix timestamp.
     * @param tip_height Current active chain tip height.
     * @return true if newly written, false if already existed or error.
     */
    bool WriteFirstSeen(const uint256& block_hash, int64_t now, int32_t tip_height);

    /**
     * Read metadata for a block.
     * @param block_hash Hash of the block.
     * @return BlockMeta if found, std::nullopt if not in database.
     */
    std::optional<BlockMeta> Read(const uint256& block_hash) const;

    /**
     * Check if metadata exists for a block (without full read).
     */
    bool Exists(const uint256& block_hash) const;

    /**
     * Get first_seen_ts for a block, or 0 if unknown.
     * Convenience wrapper around Read().
     */
    int64_t GetFirstSeenTs(const uint256& block_hash) const;

    /**
     * Flush any pending writes to disk.
     * Called periodically and on shutdown.
     */
    void Flush();

    /**
     * Clear the in-memory cache (for testing or memory pressure).
     */
    void ClearCache();

    /**
     * Delete metadata entries where first_seen_height is at or below the given height.
     * Used to clean up entries for pruned blocks to prevent database bloat.
     *
     * @param max_height Delete entries with first_seen_height <= max_height.
     * @return Number of entries deleted.
     */
    size_t PruneBefore(int32_t max_height);

    /**
     * Get approximate number of entries in the database.
     * Useful for monitoring database growth.
     */
    size_t GetEntryCount() const;

    //! @returns filesystem path to on-disk storage or std::nullopt if in memory.
    std::optional<fs::path> StoragePath() const;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKMETA_H
