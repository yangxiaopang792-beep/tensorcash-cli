// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINS_ASSET_DELTA_H
#define BITCOIN_COINS_ASSET_DELTA_H

#include <assets/icu_payload.h>
#include <assets/registry.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

/**
 * In-memory staging buffer for asset-registry mutations. Like the coin cache
 * (CCoinsViewCache::cacheCoins), it does NOT correspond to a single block: it
 * accumulates the policy / ticker / verifying-key / ICU changes from every block
 * connected or disconnected since the last flush, and the whole composed delta is
 * committed at once. Later writes to the same key supersede earlier ones.
 *
 * Part of the asset-registry atomicity refactor. The registry used to be mutated
 * through standalone CCoinsViewDB write methods (separate CDBBatch / WriteBatch
 * per call) on a different durability cadence than the periodic coins-cache
 * flush, so a crash could leave the registry best block ahead of (or behind) the
 * UTXO best block.
 *
 * Instead, mutations are staged into this delta (CCoinsViewCache carries one),
 * reads consult the delta first and the base view second, and the whole delta is
 * committed in the SAME final CDBBatch as DB_BEST_BLOCK / DB_ASSET_BEST_BLOCK
 * (CCoinsViewDB::BatchWrite) — so the asset registry and the UTXO best-block
 * marker advance together, or neither does. (The earlier partial coin batches are
 * still written separately, as in stock chainstate; only the final best-block
 * commit is atomic with the asset delta.)
 *
 * Each entry records whether it is a write or an erase; the undo data needed to
 * reverse a block lives in CBlockUndo (reg_undo / fee_undo / vk_undo / icu_undo /
 * scalar_undo). Undo entries MUST be applied in reverse on disconnect (see
 * validation.cpp DisconnectBlock) so multiple same-key mutations in one block
 * unwind correctly — e.g. two scalar epochs for one feed restore the head in order.
 *
 * Wired in: overlay reads (CCoinsViewCache) and the batched commit
 * (CCoinsViewDB::BatchWrite). Still to come: ConnectBlock/DisconnectBlock stage
 * into the view instead of writing the DB directly (replacing
 * BeginAssetRegistryUpdate/CommitAssetRegistryUpdate), and asset-safe replay. Fee
 * accumulation is folded into the staged policy entry at that point (read policy
 * through the view, add the fee, re-stage), so no separate fee channel is needed.
 */
struct CAssetRegistryDelta {
    template <typename V>
    struct Op {
        V value{};
        bool erased{false};
    };

    // Asset policy writes/erases, keyed by asset id (prefix 'R').
    std::map<uint256, Op<AssetRegistryEntry>> policy;

    // Ticker -> asset id bindings (prefix 'T').
    std::map<std::string, Op<uint256>> ticker;

    // ZK verifying keys, keyed by vk hash (prefix 'Z').
    std::map<uint256, Op<std::vector<unsigned char>>> vk;

    // ICU payloads, keyed by (asset id, ctxt commit) (prefix 'I').
    struct IcuKey {
        uint256 asset_id;
        uint256 ctxt_commit;
    };
    struct IcuKeyLess {
        bool operator()(const IcuKey& a, const IcuKey& b) const {
            if (a.asset_id != b.asset_id) return a.asset_id < b.asset_id;
            return a.ctxt_commit < b.ctxt_commit;
        }
    };
    std::map<IcuKey, Op<assets::IcuStorageEntry>, IcuKeyLess> icu;

    // Scalar-feed publications (CFD_GENERALISATION.md §3). Two sub-channels, both
    // staged here and committed in the SAME atomic batch as the maps above:
    //   - per-epoch entries keyed by (asset_id, feed_id, epoch)        (prefix 'S')
    //   - the mandatory head record (asset_id, feed_id) -> last_epoch  (prefix 's')
    struct ScalarKey {
        uint256 asset_id;
        uint32_t feed_id;
        uint64_t epoch;
    };
    struct ScalarKeyLess {
        bool operator()(const ScalarKey& a, const ScalarKey& b) const {
            if (a.asset_id != b.asset_id) return a.asset_id < b.asset_id;
            if (a.feed_id != b.feed_id) return a.feed_id < b.feed_id;
            return a.epoch < b.epoch;
        }
    };
    std::map<ScalarKey, Op<ScalarRecord>, ScalarKeyLess> scalar;

    struct ScalarHeadKey {
        uint256 asset_id;
        uint32_t feed_id;
    };
    struct ScalarHeadKeyLess {
        bool operator()(const ScalarHeadKey& a, const ScalarHeadKey& b) const {
            if (a.asset_id != b.asset_id) return a.asset_id < b.asset_id;
            return a.feed_id < b.feed_id;
        }
    };
    std::map<ScalarHeadKey, Op<uint64_t>, ScalarHeadKeyLess> scalar_head;

    bool empty() const {
        return policy.empty() && ticker.empty() && vk.empty() && icu.empty()
            && scalar.empty() && scalar_head.empty();
    }

    void clear() {
        policy.clear();
        ticker.clear();
        vk.clear();
        icu.clear();
        scalar.clear();
        scalar_head.clear();
    }
};

#endif // BITCOIN_COINS_ASSET_DELTA_H
