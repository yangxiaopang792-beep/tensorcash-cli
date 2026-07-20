// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h>
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <sync.h>
#include <util/fs.h>
#include <serialize.h>
#include <assets/registry.h>
#include <assets/icu_payload.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

class COutPoint;
class uint256;

//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 16 << 20;

//! User-controlled performance and debug options.
struct CoinsViewOptions {
    //! Maximum database write batch size in bytes.
    size_t batch_write_bytes = nDefaultDbBatchSize;
    //! If non-zero, randomly exit when the database is flushed with (1/ratio)
    //! probability.
    int simulate_crash_ratio = 0;
};

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB final : public CCoinsView
{
protected:
    DBParams m_db_params;
    CoinsViewOptions m_options;
    std::unique_ptr<CDBWrapper> m_db;
public:
    explicit CCoinsViewDB(DBParams db_params, CoinsViewOptions options);

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) override;
    std::unique_ptr<CCoinsViewCursor> Cursor() const override;

    // Asset registry API
    bool ReadAssetPolicy(const uint256& aid, AssetRegistryEntry& out) const override;
    // DB_ASSET_BEST_BLOCK / DB_ASSET_HEAD_BLOCKS are now READ-ONLY here: the best
    // block is advanced inside BatchWrite (atomic with the coins) and the head-blocks
    // marker is only read by the startup recovery guard for legacy/pre-atomic
    // chainstates — nothing writes it anymore (the in-progress Begin/Commit update
    // API was removed in favor of the single atomic BatchWrite commit).
    uint256 GetAssetRegistryBestBlock() const;
    std::vector<uint256> GetAssetRegistryHeadBlocks() const;
    //! Enumerate every asset_id in the on-disk registry (DB_ASSET_REG prefix).
    //! No chain scan — reads the leveldb index the node already maintains.
    std::vector<uint256> GetAllRegisteredAssets() const;
    bool WriteAssetPolicy(const uint256& aid, const AssetRegistryEntry& in, CDBBatch& batch);
    bool EraseAssetPolicy(const uint256& aid, CDBBatch& batch);
    bool WriteAssetPolicy(const uint256& aid, const AssetRegistryEntry& in);
    bool EraseAssetPolicy(const uint256& aid);

    // Ticker index API
    bool ReadTickerBinding(const std::string& ticker, uint256& out_asset) const override;
    bool WriteTickerBinding(const std::string& ticker, const uint256& asset, CDBBatch& batch);
    bool EraseTickerBinding(const std::string& ticker, CDBBatch& batch);
    bool WriteTickerBinding(const std::string& ticker, const uint256& asset);
    bool EraseTickerBinding(const std::string& ticker);

    // ZK verifying key storage
    bool ReadZkVerifyingKey(const uint256& vk_hash, std::vector<unsigned char>& out) const override;
    bool WriteZkVerifyingKey(const uint256& vk_hash, const std::vector<unsigned char>& bytes, CDBBatch& batch);
    bool EraseZkVerifyingKey(const uint256& vk_hash, CDBBatch& batch);
    bool WriteZkVerifyingKey(const uint256& vk_hash, const std::vector<unsigned char>& bytes);
    bool EraseZkVerifyingKey(const uint256& vk_hash);

    // ICU payload storage (prefix 'I') - stores IcuStorageEntry with metadata
    bool ReadIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, assets::IcuStorageEntry& out) const override;
    bool WriteIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, const assets::IcuStorageEntry& entry, CDBBatch& batch);
    bool EraseIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, CDBBatch& batch);
    bool WriteIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, const assets::IcuStorageEntry& entry);
    bool EraseIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit);

    // Scalar-feed storage (CFD_GENERALISATION.md §3.2): per-epoch records (prefix 'S')
    // keyed by (asset_id, feed_id, epoch) and the head record (prefix 's') keyed by
    // (asset_id, feed_id) -> last_epoch. All writes flow through the atomic BatchWrite
    // via the staged CAssetRegistryDelta; only the batch-taking + read forms exist.
    bool ReadAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, ScalarRecord& out) const override;
    bool WriteAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, const ScalarRecord& rec, CDBBatch& batch);
    bool EraseAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, CDBBatch& batch);
    bool ReadAssetScalarHead(const uint256& asset_id, uint32_t feed_id, uint64_t& out_last_epoch) const override;
    bool WriteAssetScalarHead(const uint256& asset_id, uint32_t feed_id, uint64_t last_epoch, CDBBatch& batch);
    bool EraseAssetScalarHead(const uint256& asset_id, uint32_t feed_id, CDBBatch& batch);
    //! Enumerate all scalar feeds for an asset as (feed_id, last_epoch), by range-scanning
    //! the 's' head prefix (entries for one asset are contiguous). No chain scan. Callers
    //! merge CCoinsViewCache::GetStagedScalarHeads for feeds not yet flushed.
    std::vector<std::pair<uint32_t, uint64_t>> GetAssetScalarFeeds(const uint256& asset_id) const;

    //! Whether an unsupported database format is used.
    bool NeedsUpgrade();
    size_t EstimateSize() const override;

    //! Dynamically alter the underlying leveldb cache size.
    void ResizeCache(size_t new_cache_size) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! @returns filesystem path to on-disk storage or std::nullopt if in memory.
    std::optional<fs::path> StoragePath() { return m_db->StoragePath(); }
};

#endif // BITCOIN_TXDB_H
