// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <assets/icu_payload.h>
#include <assets/registry.h>
#include <coins_asset_delta.h>
#include <consensus/consensus.h>
#include <logging.h>
#include <random.h>
#include <util/trace.h>

TRACEPOINT_SEMAPHORE(utxocache, add);
TRACEPOINT_SEMAPHORE(utxocache, spent);
TRACEPOINT_SEMAPHORE(utxocache, uncache);

namespace {
// Approximate dynamic memory of a staged asset delta. Precise enough to make
// large staged payloads — especially ICU blobs (up to 100 KiB) — count toward
// the cache's flush threshold so the overlay stays bounded.
size_t AssetDeltaDynamicUsage(const CAssetRegistryDelta& d)
{
    // Approximate (lower bound): captures the dominant dynamic memory — ICU blobs
    // (up to 100 KiB), VK payloads, and the policy entry's variable-length parts
    // (ticker + the compliance/rotation history deques) — enough to make large
    // staged payloads count toward the cache's flush threshold.
    constexpr size_t kNode = 64; // rough per-entry map-node overhead
    auto policy_usage = [](const AssetRegistryEntry& e) {
        return sizeof(AssetRegistryEntry) + e.ticker.size()
             + e.compliance_root_history.size() * sizeof(ComplianceRootHistory)
             + e.rotation_history.size() * sizeof(IssuerRegSnapshot);
    };
    size_t u = 0;
    for (const auto& [k, op] : d.policy) u += kNode + (op.erased ? 0 : policy_usage(op.value));
    for (const auto& [k, op] : d.ticker) u += kNode + k.size() + (op.erased ? 0 : sizeof(uint256));
    for (const auto& [k, op] : d.vk)     u += kNode + (op.erased ? 0 : op.value.size());
    for (const auto& [k, op] : d.icu)    u += kNode + (op.erased ? 0 : sizeof(assets::IcuStorageEntry) + op.value.icu_cipher.size());
    for (const auto& [k, op] : d.scalar)      u += kNode + (op.erased ? 0 : sizeof(ScalarRecord));
    for (const auto& [k, op] : d.scalar_head) u += kNode + (op.erased ? 0 : sizeof(uint64_t));
    return u;
}
} // namespace

std::optional<Coin> CCoinsView::GetCoin(const COutPoint& outpoint) const { return std::nullopt; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) { return false; }
std::unique_ptr<CCoinsViewCursor> CCoinsView::Cursor() const { return nullptr; }

// Default asset-registry reads: a view with no asset state reports "not found".
// Overridden by CCoinsViewDB; forwarded by CCoinsViewBacked.
bool CCoinsView::ReadAssetPolicy(const uint256&, AssetRegistryEntry&) const { return false; }
bool CCoinsView::ReadTickerBinding(const std::string&, uint256&) const { return false; }
bool CCoinsView::ReadZkVerifyingKey(const uint256&, std::vector<unsigned char>&) const { return false; }
bool CCoinsView::ReadIcuPayload(const uint256&, const uint256&, assets::IcuStorageEntry&) const { return false; }
bool CCoinsView::ReadAssetScalar(const uint256&, uint32_t, uint64_t, ScalarRecord&) const { return false; }
bool CCoinsView::ReadAssetScalarHead(const uint256&, uint32_t, uint64_t&) const { return false; }

bool CCoinsView::HaveCoin(const COutPoint &outpoint) const
{
    return GetCoin(outpoint).has_value();
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
std::optional<Coin> CCoinsViewBacked::GetCoin(const COutPoint& outpoint) const { return base->GetCoin(outpoint); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) { return base->BatchWrite(cursor, hashBlock); }
std::unique_ptr<CCoinsViewCursor> CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }

CCoinsViewCache::CCoinsViewCache(CCoinsView* baseIn, bool deterministic) :
    CCoinsViewBacked(baseIn), m_deterministic(deterministic),
    cacheCoins(0, SaltedOutpointHasher(/*deterministic=*/deterministic), CCoinsMap::key_equal{}, &m_cache_coins_memory_resource)
{
    m_sentinel.second.SelfRef(m_sentinel);
}

CCoinsViewCache::~CCoinsViewCache() = default;

CAssetRegistryDelta& CCoinsViewCache::EnsureDelta() {
    if (!m_asset_delta) m_asset_delta = std::make_unique<CAssetRegistryDelta>();
    return *m_asset_delta;
}

// Asset-registry overlay reads: staged op wins (write returns value, erase reports
// not-found); otherwise fall through to the base view.
bool CCoinsViewCache::ReadAssetPolicy(const uint256& aid, AssetRegistryEntry& out) const {
    if (m_asset_delta) {
        if (auto it = m_asset_delta->policy.find(aid); it != m_asset_delta->policy.end()) {
            if (it->second.erased) return false;
            out = it->second.value;
            return true;
        }
    }
    return base->ReadAssetPolicy(aid, out);
}

bool CCoinsViewCache::ReadTickerBinding(const std::string& ticker, uint256& out_asset) const {
    if (m_asset_delta) {
        if (auto it = m_asset_delta->ticker.find(ticker); it != m_asset_delta->ticker.end()) {
            if (it->second.erased) return false;
            out_asset = it->second.value;
            return true;
        }
    }
    return base->ReadTickerBinding(ticker, out_asset);
}

bool CCoinsViewCache::ReadZkVerifyingKey(const uint256& vk_hash, std::vector<unsigned char>& out) const {
    if (m_asset_delta) {
        if (auto it = m_asset_delta->vk.find(vk_hash); it != m_asset_delta->vk.end()) {
            if (it->second.erased) return false;
            out = it->second.value;
            return true;
        }
    }
    return base->ReadZkVerifyingKey(vk_hash, out);
}

bool CCoinsViewCache::ReadIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, assets::IcuStorageEntry& out) const {
    if (m_asset_delta) {
        const CAssetRegistryDelta::IcuKey key{asset_id, icu_ctxt_commit};
        if (auto it = m_asset_delta->icu.find(key); it != m_asset_delta->icu.end()) {
            if (it->second.erased) return false;
            out = it->second.value;
            return true;
        }
    }
    return base->ReadIcuPayload(asset_id, icu_ctxt_commit, out);
}

bool CCoinsViewCache::ReadAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, ScalarRecord& out) const {
    if (m_asset_delta) {
        const CAssetRegistryDelta::ScalarKey key{asset_id, feed_id, epoch};
        if (auto it = m_asset_delta->scalar.find(key); it != m_asset_delta->scalar.end()) {
            if (it->second.erased) return false;
            out = it->second.value;
            return true;
        }
    }
    return base->ReadAssetScalar(asset_id, feed_id, epoch, out);
}

bool CCoinsViewCache::ReadAssetScalarHead(const uint256& asset_id, uint32_t feed_id, uint64_t& out_last_epoch) const {
    if (m_asset_delta) {
        const CAssetRegistryDelta::ScalarHeadKey key{asset_id, feed_id};
        if (auto it = m_asset_delta->scalar_head.find(key); it != m_asset_delta->scalar_head.end()) {
            if (it->second.erased) return false;
            out_last_epoch = it->second.value;
            return true;
        }
    }
    return base->ReadAssetScalarHead(asset_id, feed_id, out_last_epoch);
}

// Asset-registry overlay staging: later ops to the same key supersede earlier ones.
void CCoinsViewCache::StageAssetPolicy(const uint256& aid, const AssetRegistryEntry& entry) {
    auto& op = EnsureDelta().policy[aid];
    op.value = entry;
    op.erased = false;
}
void CCoinsViewCache::StageEraseAssetPolicy(const uint256& aid) {
    auto& op = EnsureDelta().policy[aid];
    op = {};
    op.erased = true;
}
void CCoinsViewCache::StageTickerBinding(const std::string& ticker, const uint256& asset) {
    auto& op = EnsureDelta().ticker[ticker];
    op.value = asset;
    op.erased = false;
}
void CCoinsViewCache::StageEraseTickerBinding(const std::string& ticker) {
    auto& op = EnsureDelta().ticker[ticker];
    op = {};
    op.erased = true;
}
void CCoinsViewCache::StageZkVerifyingKey(const uint256& vk_hash, const std::vector<unsigned char>& payload) {
    auto& op = EnsureDelta().vk[vk_hash];
    op.value = payload;
    op.erased = false;
}
void CCoinsViewCache::StageEraseZkVerifyingKey(const uint256& vk_hash) {
    auto& op = EnsureDelta().vk[vk_hash];
    op = {};
    op.erased = true;
}
void CCoinsViewCache::StageIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit, const assets::IcuStorageEntry& entry) {
    auto& op = EnsureDelta().icu[CAssetRegistryDelta::IcuKey{asset_id, icu_ctxt_commit}];
    op.value = entry;
    op.erased = false;
}
void CCoinsViewCache::StageEraseIcuPayload(const uint256& asset_id, const uint256& icu_ctxt_commit) {
    auto& op = EnsureDelta().icu[CAssetRegistryDelta::IcuKey{asset_id, icu_ctxt_commit}];
    op = {};
    op.erased = true;
}
void CCoinsViewCache::StageAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch, const ScalarRecord& record) {
    auto& op = EnsureDelta().scalar[CAssetRegistryDelta::ScalarKey{asset_id, feed_id, epoch}];
    op.value = record;
    op.erased = false;
}
void CCoinsViewCache::StageEraseAssetScalar(const uint256& asset_id, uint32_t feed_id, uint64_t epoch) {
    auto& op = EnsureDelta().scalar[CAssetRegistryDelta::ScalarKey{asset_id, feed_id, epoch}];
    op = {};
    op.erased = true;
}
void CCoinsViewCache::StageAssetScalarHead(const uint256& asset_id, uint32_t feed_id, uint64_t last_epoch) {
    auto& op = EnsureDelta().scalar_head[CAssetRegistryDelta::ScalarHeadKey{asset_id, feed_id}];
    op.value = last_epoch;
    op.erased = false;
}
void CCoinsViewCache::StageEraseAssetScalarHead(const uint256& asset_id, uint32_t feed_id) {
    auto& op = EnsureDelta().scalar_head[CAssetRegistryDelta::ScalarHeadKey{asset_id, feed_id}];
    op = {};
    op.erased = true;
}

void CCoinsViewCache::GetStagedAssetPolicyIds(std::vector<uint256>& added, std::vector<uint256>& erased) const {
    if (!m_asset_delta) return;
    for (const auto& [aid, op] : m_asset_delta->policy) {
        (op.erased ? erased : added).push_back(aid);
    }
}

void CCoinsViewCache::GetStagedScalarHeads(const uint256& asset_id,
                                           std::vector<std::pair<uint32_t, uint64_t>>& added,
                                           std::vector<uint32_t>& erased) const {
    if (!m_asset_delta) return;
    for (const auto& [k, op] : m_asset_delta->scalar_head) {
        if (k.asset_id != asset_id) continue;
        if (op.erased) erased.push_back(k.feed_id);
        else added.emplace_back(k.feed_id, op.value);
    }
}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    size_t usage = memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
    if (m_asset_delta) usage += AssetDeltaDynamicUsage(*m_asset_delta);
    return usage;
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    const auto [ret, inserted] = cacheCoins.try_emplace(outpoint);
    if (inserted) {
        if (auto coin{base->GetCoin(outpoint)}) {
            ret->second.coin = std::move(*coin);
            cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
            if (ret->second.coin.IsSpent()) { // TODO GetCoin cannot return spent coins
                // The parent only has an empty entry for this outpoint; we can consider our version as fresh.
                CCoinsCacheEntry::SetFresh(*ret, m_sentinel);
            }
        } else {
            cacheCoins.erase(ret);
            return cacheCoins.end();
        }
    }
    return ret;
}

std::optional<Coin> CCoinsViewCache::GetCoin(const COutPoint& outpoint) const
{
    if (auto it{FetchCoin(outpoint)}; it != cacheCoins.end() && !it->second.coin.IsSpent()) return it->second.coin;
    return std::nullopt;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Attempted to overwrite an unspent coin (when possible_overwrite is false)");
        }
        // If the coin exists in this cache as a spent coin and is DIRTY, then
        // its spentness hasn't been flushed to the parent cache. We're
        // re-adding the coin to this cache now but we can't mark it as FRESH.
        // If we mark it FRESH and then spend it before the cache is flushed
        // we would remove it from this cache and would never flush spentness
        // to the parent cache.
        //
        // Re-adding a spent coin can happen in the case of a re-org (the coin
        // is 'spent' when the block adding it is disconnected and then
        // re-added when it is also added in a newly connected block).
        //
        // If the coin doesn't exist in the current cache, or is spent but not
        // DIRTY, then it can be marked FRESH.
        fresh = !it->second.IsDirty();
    }
    it->second.coin = std::move(coin);
    CCoinsCacheEntry::SetDirty(*it, m_sentinel);
    if (fresh) CCoinsCacheEntry::SetFresh(*it, m_sentinel);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
    TRACEPOINT(utxocache, add,
           outpoint.hash.data(),
           (uint32_t)outpoint.n,
           (uint32_t)it->second.coin.nHeight,
           (int64_t)it->second.coin.out.nValue,
           (bool)it->second.coin.IsCoinBase());
}

void CCoinsViewCache::EmplaceCoinInternalDANGER(COutPoint&& outpoint, Coin&& coin) {
    cachedCoinsUsage += coin.DynamicMemoryUsage();
    auto [it, inserted] = cacheCoins.try_emplace(std::move(outpoint), std::move(coin));
    if (inserted) CCoinsCacheEntry::SetDirty(*it, m_sentinel);
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check_for_overwrite) {
    bool fCoinbase = tx.IsCoinBase();
    const Txid& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check_for_overwrite ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Coinbase transactions can always be overwritten, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;
    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    TRACEPOINT(utxocache, spent,
           outpoint.hash.data(),
           (uint32_t)outpoint.n,
           (uint32_t)it->second.coin.nHeight,
           (int64_t)it->second.coin.out.nValue,
           (bool)it->second.coin.IsCoinBase());
    if (moveout) {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.IsFresh()) {
        cacheCoins.erase(it);
    } else {
        CCoinsCacheEntry::SetDirty(*it, m_sentinel);
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlockIn) {
    for (auto it{cursor.Begin()}; it != cursor.End(); it = cursor.NextAndMaybeErase(*it)) {
        // Ignore non-dirty entries (optimization).
        if (!it->second.IsDirty()) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child cache does.
            // We can ignore it if it's both spent and FRESH in the child
            if (!(it->second.IsFresh() && it->second.coin.IsSpent())) {
                // Create the coin in the parent cache, move the data up
                // and mark it as dirty.
                itUs = cacheCoins.try_emplace(it->first).first;
                CCoinsCacheEntry& entry{itUs->second};
                if (cursor.WillErase(*it)) {
                    // Since this entry will be erased,
                    // we can move the coin into us instead of copying it
                    entry.coin = std::move(it->second.coin);
                } else {
                    entry.coin = it->second.coin;
                }
                cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                CCoinsCacheEntry::SetDirty(*itUs, m_sentinel);
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.IsFresh()) CCoinsCacheEntry::SetFresh(*itUs, m_sentinel);
            }
        } else {
            // Found the entry in the parent cache
            if (it->second.IsFresh() && !itUs->second.coin.IsSpent()) {
                // The coin was marked FRESH in the child cache, but the coin
                // exists in the parent cache. If this ever happens, it means
                // the FRESH flag was misapplied and there is a logic error in
                // the calling code.
                throw std::logic_error("FRESH flag misapplied to coin that exists in parent cache");
            }

            if (itUs->second.IsFresh() && it->second.coin.IsSpent()) {
                // The grandparent cache does not have an entry, and the coin
                // has been spent. We can just delete it from the parent cache.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                cacheCoins.erase(itUs);
            } else {
                // A normal modification.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                if (cursor.WillErase(*it)) {
                    // Since this entry will be erased,
                    // we can move the coin into us instead of copying it
                    itUs->second.coin = std::move(it->second.coin);
                } else {
                    itUs->second.coin = it->second.coin;
                }
                cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                CCoinsCacheEntry::SetDirty(*itUs, m_sentinel);
                // NOTE: It isn't safe to mark the coin as FRESH in the parent
                // cache. If it already existed and was spent in the parent
                // cache then marking it FRESH would prevent that spentness
                // from being flushed to the grandparent.
            }
        }
    }
    hashBlock = hashBlockIn;

    // Merge an incoming asset delta (a child cache flushing into this one) into
    // our overlay, composing so the child's ops supersede ours for shared keys.
    if (const CAssetRegistryDelta* child = cursor.AssetDelta(); child && !child->empty()) {
        CAssetRegistryDelta& parent = EnsureDelta();
        for (const auto& [k, op] : child->policy) parent.policy[k] = op;
        for (const auto& [k, op] : child->ticker) parent.ticker[k] = op;
        for (const auto& [k, op] : child->vk) parent.vk[k] = op;
        for (const auto& [k, op] : child->icu) parent.icu[k] = op;
        for (const auto& [k, op] : child->scalar) parent.scalar[k] = op;
        for (const auto& [k, op] : child->scalar_head) parent.scalar_head[k] = op;
    }
    return true;
}

bool CCoinsViewCache::Flush() {
    auto cursor{CoinsViewCacheCursor(cachedCoinsUsage, m_sentinel, cacheCoins, /*will_erase=*/true)};
    cursor.SetAssetDelta(m_asset_delta.get());
    bool fOk = base->BatchWrite(cursor, hashBlock);
    if (fOk) {
        cacheCoins.clear();
        ReallocateCache();
        m_asset_delta.reset();
    }
    cachedCoinsUsage = 0;
    return fOk;
}

bool CCoinsViewCache::Sync()
{
    auto cursor{CoinsViewCacheCursor(cachedCoinsUsage, m_sentinel, cacheCoins, /*will_erase=*/false)};
    cursor.SetAssetDelta(m_asset_delta.get());
    bool fOk = base->BatchWrite(cursor, hashBlock);
    if (fOk) {
        if (m_sentinel.second.Next() != &m_sentinel) {
            /* BatchWrite must clear flags of all entries */
            throw std::logic_error("Not all unspent flagged entries were cleared");
        }
        // The base now holds the staged asset state; drop our overlay copy.
        m_asset_delta.reset();
    }
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& hash)
{
    CCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && !it->second.IsDirty() && !it->second.IsFresh()) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        TRACEPOINT(utxocache, uncache,
               hash.hash.data(),
               (uint32_t)hash.n,
               (uint32_t)it->second.coin.nHeight,
               (int64_t)it->second.coin.out.nValue,
               (bool)it->second.coin.IsCoinBase());
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

void CCoinsViewCache::ReallocateCache()
{
    // Cache should be empty when we're calling this.
    assert(cacheCoins.size() == 0);
    cacheCoins.~CCoinsMap();
    m_cache_coins_memory_resource.~CCoinsMapMemoryResource();
    ::new (&m_cache_coins_memory_resource) CCoinsMapMemoryResource{};
    ::new (&cacheCoins) CCoinsMap{0, SaltedOutpointHasher{/*deterministic=*/m_deterministic}, CCoinsMap::key_equal{}, &m_cache_coins_memory_resource};
}

void CCoinsViewCache::SanityCheck() const
{
    size_t recomputed_usage = 0;
    size_t count_flagged = 0;
    for (const auto& [_, entry] : cacheCoins) {
        unsigned attr = 0;
        if (entry.IsDirty()) attr |= 1;
        if (entry.IsFresh()) attr |= 2;
        if (entry.coin.IsSpent()) attr |= 4;
        // Only 5 combinations are possible.
        assert(attr != 2 && attr != 4 && attr != 7);

        // Recompute cachedCoinsUsage.
        recomputed_usage += entry.coin.DynamicMemoryUsage();

        // Count the number of entries we expect in the linked list.
        if (entry.IsDirty() || entry.IsFresh()) ++count_flagged;
    }
    // Iterate over the linked list of flagged entries.
    size_t count_linked = 0;
    for (auto it = m_sentinel.second.Next(); it != &m_sentinel; it = it->second.Next()) {
        // Verify linked list integrity.
        assert(it->second.Next()->second.Prev() == it);
        assert(it->second.Prev()->second.Next() == it);
        // Verify they are actually flagged.
        assert(it->second.IsDirty() || it->second.IsFresh());
        // Count the number of entries actually in the list.
        ++count_linked;
    }
    assert(count_linked == count_flagged);
    assert(recomputed_usage == cachedCoinsUsage);
}

static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxOut());
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;

const Coin& AccessByTxid(const CCoinsViewCache& view, const Txid& txid)
{
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}

template <typename ReturnType, typename Func>
static ReturnType ExecuteBackedWrapper(Func func, const std::vector<std::function<void()>>& err_callbacks)
{
    try {
        return func();
    } catch(const std::runtime_error& e) {
        for (const auto& f : err_callbacks) {
            f();
        }
        LogError("Error reading from database: %s\n", e.what());
        // Starting the shutdown sequence and returning false to the caller would be
        // interpreted as 'entry not found' (as opposed to unable to read data), and
        // could lead to invalid interpretation. Just exit immediately, as we can't
        // continue anyway, and all writes should be atomic.
        std::abort();
    }
}

std::optional<Coin> CCoinsViewErrorCatcher::GetCoin(const COutPoint& outpoint) const
{
    return ExecuteBackedWrapper<std::optional<Coin>>([&]() { return CCoinsViewBacked::GetCoin(outpoint); }, m_err_callbacks);
}

bool CCoinsViewErrorCatcher::HaveCoin(const COutPoint& outpoint) const
{
    return ExecuteBackedWrapper<bool>([&]() { return CCoinsViewBacked::HaveCoin(outpoint); }, m_err_callbacks);
}
