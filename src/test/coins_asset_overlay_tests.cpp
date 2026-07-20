// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Overlay semantics for the asset-registry staging buffer carried by
// CCoinsViewCache (see CAssetRegistryDelta). For each of policy / ticker / VK /
// ICU: a staged write beats the base value, a staged erase masks the base, a
// later stage to the same key composes (supersedes), and a staged key absent
// from the base is still visible.

#include <coins.h>
#include <coins_asset_delta.h>
#include <txdb.h>

#include <assets/asset.h>
#include <assets/icu_payload.h>
#include <assets/registry.h>
#include <primitives/transaction.h>
#include <undo.h>
#include <script/script.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

// Minimal base view that answers asset reads from in-memory maps.
struct AssetBaseStub : public CCoinsView {
    std::map<uint256, AssetRegistryEntry> policy;
    std::map<std::string, uint256> ticker;
    std::map<uint256, std::vector<unsigned char>> vk;
    std::map<std::pair<uint256, uint256>, assets::IcuStorageEntry> icu;
    std::map<std::tuple<uint256, uint32_t, uint64_t>, ScalarRecord> scalar;
    std::map<std::pair<uint256, uint32_t>, uint64_t> scalar_head;

    bool ReadAssetPolicy(const uint256& aid, AssetRegistryEntry& out) const override {
        auto it = policy.find(aid);
        if (it == policy.end()) return false;
        out = it->second;
        return true;
    }
    bool ReadTickerBinding(const std::string& t, uint256& out) const override {
        auto it = ticker.find(t);
        if (it == ticker.end()) return false;
        out = it->second;
        return true;
    }
    bool ReadZkVerifyingKey(const uint256& h, std::vector<unsigned char>& out) const override {
        auto it = vk.find(h);
        if (it == vk.end()) return false;
        out = it->second;
        return true;
    }
    bool ReadIcuPayload(const uint256& a, const uint256& c, assets::IcuStorageEntry& out) const override {
        auto it = icu.find({a, c});
        if (it == icu.end()) return false;
        out = it->second;
        return true;
    }
    bool ReadAssetScalar(const uint256& a, uint32_t f, uint64_t e, ScalarRecord& out) const override {
        auto it = scalar.find({a, f, e});
        if (it == scalar.end()) return false;
        out = it->second;
        return true;
    }
    bool ReadAssetScalarHead(const uint256& a, uint32_t f, uint64_t& out) const override {
        auto it = scalar_head.find({a, f});
        if (it == scalar_head.end()) return false;
        out = it->second;
        return true;
    }
};

constexpr uint256 AID_A{"0000000000000000000000000000000000000000000000000000000000000001"};
constexpr uint256 AID_B{"0000000000000000000000000000000000000000000000000000000000000002"};
constexpr uint256 CTX{"00000000000000000000000000000000000000000000000000000000000000aa"};
constexpr uint256 BLK{"00000000000000000000000000000000000000000000000000000000000000ff"};

AssetRegistryEntry Policy(uint8_t decimals, uint32_t policy_bits)
{
    AssetRegistryEntry e;
    e.decimals = decimals;
    e.policy_bits = policy_bits;
    return e;
}

assets::IcuStorageEntry Icu(unsigned char tag)
{
    assets::IcuStorageEntry e;
    e.icu_cipher = {tag};
    return e;
}

ScalarRecord ScalarRec(unsigned char tag, int32_t height = 7)
{
    ScalarRecord r;
    r.scalar.begin()[0] = tag; // distinguishable raw value
    r.publication_height = height;
    r.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    return r;
}

// A base view whose BatchWrite always fails, to prove a failed flush does not
// silently drop the staged asset delta.
struct FailingBatchWriteView : public AssetBaseStub {
    bool BatchWrite(CoinsViewCacheCursor&, const uint256&) override { return false; }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(coins_asset_overlay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(policy_overlay)
{
    AssetBaseStub base;
    base.policy[AID_A] = Policy(8, 0x1);
    CCoinsViewCache cache(&base);

    AssetRegistryEntry got;
    BOOST_CHECK(cache.ReadAssetPolicy(AID_A, got));      // base visible through cache
    BOOST_CHECK_EQUAL(int(got.decimals), 8);

    cache.StageAssetPolicy(AID_A, Policy(2, 0x9));       // staged write beats base
    BOOST_CHECK(cache.ReadAssetPolicy(AID_A, got));
    BOOST_CHECK_EQUAL(int(got.decimals), 2);
    BOOST_CHECK_EQUAL(got.policy_bits, 0x9u);

    cache.StageAssetPolicy(AID_A, Policy(5, 0x7));       // overwrite composes (latest wins)
    BOOST_CHECK(cache.ReadAssetPolicy(AID_A, got));
    BOOST_CHECK_EQUAL(int(got.decimals), 5);

    cache.StageEraseAssetPolicy(AID_A);                  // erase masks base
    BOOST_CHECK(!cache.ReadAssetPolicy(AID_A, got));

    cache.StageAssetPolicy(AID_A, Policy(3, 0x2));       // re-stage after erase
    BOOST_CHECK(cache.ReadAssetPolicy(AID_A, got));
    BOOST_CHECK_EQUAL(int(got.decimals), 3);

    BOOST_CHECK(!cache.ReadAssetPolicy(AID_B, got));     // key absent in base...
    cache.StageAssetPolicy(AID_B, Policy(6, 0x4));       // ...visible once staged
    BOOST_CHECK(cache.ReadAssetPolicy(AID_B, got));
    BOOST_CHECK_EQUAL(int(got.decimals), 6);
}

BOOST_AUTO_TEST_CASE(ticker_overlay)
{
    AssetBaseStub base;
    base.ticker["FOO"] = AID_A;
    CCoinsViewCache cache(&base);

    uint256 got;
    BOOST_CHECK(cache.ReadTickerBinding("FOO", got));
    BOOST_CHECK(got == AID_A);

    cache.StageTickerBinding("FOO", AID_B);              // staged write beats base
    BOOST_CHECK(cache.ReadTickerBinding("FOO", got));
    BOOST_CHECK(got == AID_B);

    cache.StageEraseTickerBinding("FOO");                // erase masks base
    BOOST_CHECK(!cache.ReadTickerBinding("FOO", got));

    cache.StageTickerBinding("BAR", AID_A);              // key absent in base
    BOOST_CHECK(cache.ReadTickerBinding("BAR", got));
    BOOST_CHECK(got == AID_A);
}

BOOST_AUTO_TEST_CASE(vk_overlay)
{
    using Bytes = std::vector<unsigned char>;
    AssetBaseStub base;
    base.vk[AID_A] = Bytes{1, 2, 3};
    CCoinsViewCache cache(&base);

    Bytes got;
    BOOST_CHECK(cache.ReadZkVerifyingKey(AID_A, got));
    BOOST_CHECK(got == Bytes({1, 2, 3}));

    cache.StageZkVerifyingKey(AID_A, Bytes{4, 5});       // staged write beats base
    BOOST_CHECK(cache.ReadZkVerifyingKey(AID_A, got));
    BOOST_CHECK(got == Bytes({4, 5}));

    cache.StageZkVerifyingKey(AID_A, Bytes{6});          // overwrite composes
    BOOST_CHECK(cache.ReadZkVerifyingKey(AID_A, got));
    BOOST_CHECK(got == Bytes({6}));

    cache.StageEraseZkVerifyingKey(AID_A);               // erase masks base
    BOOST_CHECK(!cache.ReadZkVerifyingKey(AID_A, got));
}

BOOST_AUTO_TEST_CASE(icu_overlay)
{
    using Bytes = std::vector<unsigned char>;
    AssetBaseStub base;
    base.icu[{AID_A, CTX}] = Icu(0x11);
    CCoinsViewCache cache(&base);

    assets::IcuStorageEntry got;
    BOOST_CHECK(cache.ReadIcuPayload(AID_A, CTX, got));
    BOOST_CHECK(got.icu_cipher == Bytes({0x11}));

    cache.StageIcuPayload(AID_A, CTX, Icu(0x22));        // staged write beats base
    BOOST_CHECK(cache.ReadIcuPayload(AID_A, CTX, got));
    BOOST_CHECK(got.icu_cipher == Bytes({0x22}));

    cache.StageEraseIcuPayload(AID_A, CTX);              // erase masks base
    BOOST_CHECK(!cache.ReadIcuPayload(AID_A, CTX, got));

    cache.StageIcuPayload(AID_A, AID_B, Icu(0x33));      // distinct (aid, ctxt) key is independent
    BOOST_CHECK(cache.ReadIcuPayload(AID_A, AID_B, got));
    BOOST_CHECK(got.icu_cipher == Bytes({0x33}));
}

// Slice 4: a staged delta is committed to the backing CCoinsViewDB on Flush, and
// DB_ASSET_BEST_BLOCK advances to the coins best block.
BOOST_AUTO_TEST_CASE(commit_to_db)
{
    using Bytes = std::vector<unsigned char>;
    CCoinsViewDB db{{.path = "overlay_commit", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache cache(&db);
    cache.SetBestBlock(BLK);

    cache.StageAssetPolicy(AID_A, Policy(7, 0x5));
    cache.StageTickerBinding("ZZZ", AID_B);
    cache.StageZkVerifyingKey(AID_A, Bytes{9, 9, 9});
    cache.StageIcuPayload(AID_A, CTX, Icu(0x44));
    BOOST_CHECK(cache.Flush());

    AssetRegistryEntry p;
    BOOST_CHECK(db.ReadAssetPolicy(AID_A, p));
    BOOST_CHECK_EQUAL(int(p.decimals), 7);
    uint256 t;
    BOOST_CHECK(db.ReadTickerBinding("ZZZ", t));
    BOOST_CHECK(t == AID_B);
    Bytes v;
    BOOST_CHECK(db.ReadZkVerifyingKey(AID_A, v));
    BOOST_CHECK(v == Bytes({9, 9, 9}));
    assets::IcuStorageEntry ic;
    BOOST_CHECK(db.ReadIcuPayload(AID_A, CTX, ic));
    BOOST_CHECK(ic.icu_cipher == Bytes({0x44}));
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == BLK);  // asset best tracks coins best

    // A staged erase commits as a delete; asset best advances again.
    CCoinsViewCache cache2(&db);
    cache2.SetBestBlock(AID_B);
    cache2.StageEraseAssetPolicy(AID_A);
    BOOST_CHECK(cache2.Flush());
    BOOST_CHECK(!db.ReadAssetPolicy(AID_A, p));
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == AID_B);
}

// Guardrail: the asset delta commits in the FINAL batch even when the coins are
// split across multiple partial batches (batch_write_bytes forced tiny).
BOOST_AUTO_TEST_CASE(commit_with_partial_coin_batches)
{
    using Bytes = std::vector<unsigned char>;
    CoinsViewOptions opts;
    opts.batch_write_bytes = 1; // force a partial WriteBatch per coin
    CCoinsViewDB db{{.path = "overlay_partial", .cache_bytes = 1 << 20, .memory_only = true}, opts};
    CCoinsViewCache cache(&db);
    cache.SetBestBlock(BLK);

    const Txid txid = Txid::FromUint256(AID_A);
    for (uint32_t n = 0; n < 8; ++n) {
        cache.AddCoin(COutPoint{txid, n}, Coin(CTxOut(1000, CScript()), 1, false), false);
    }
    cache.StageIcuPayload(AID_A, CTX, Icu(0x55));
    BOOST_CHECK(cache.Flush());

    assets::IcuStorageEntry ic;
    BOOST_CHECK(db.ReadIcuPayload(AID_A, CTX, ic));  // committed despite partial coin batches
    BOOST_CHECK(ic.icu_cipher == Bytes({0x55}));
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == BLK);
}

// Cache-to-cache merge: a child cache's staged ops compose into the parent on
// flush (child supersedes), and the parent's flush carries the result to the DB.
BOOST_AUTO_TEST_CASE(nested_cache_merge)
{
    using Bytes = std::vector<unsigned char>;
    CCoinsViewDB db{{.path = "overlay_nested", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache parent(&db);
    CCoinsViewCache child(&parent);

    parent.StageAssetPolicy(AID_A, Policy(1, 0x1));
    parent.StageTickerBinding("FOO", AID_A);
    child.StageAssetPolicy(AID_A, Policy(9, 0x9)); // child overwrites parent's policy
    child.StageEraseTickerBinding("FOO");           // child erases parent's binding
    child.StageZkVerifyingKey(AID_B, Bytes{7});

    AssetRegistryEntry p;
    BOOST_CHECK(parent.ReadAssetPolicy(AID_A, p) && int(p.decimals) == 1); // parent unaffected pre-flush

    child.SetBestBlock(BLK);
    BOOST_CHECK(child.Flush()); // child -> parent

    BOOST_CHECK(parent.ReadAssetPolicy(AID_A, p) && int(p.decimals) == 9); // child composed in
    uint256 t;
    BOOST_CHECK(!parent.ReadTickerBinding("FOO", t)); // erased by child
    Bytes v;
    BOOST_CHECK(parent.ReadZkVerifyingKey(AID_B, v) && v == Bytes{7});

    parent.SetBestBlock(BLK);
    BOOST_CHECK(parent.Flush()); // parent -> DB

    BOOST_CHECK(db.ReadAssetPolicy(AID_A, p) && int(p.decimals) == 9);
    BOOST_CHECK(!db.ReadTickerBinding("FOO", t));
    BOOST_CHECK(db.ReadZkVerifyingKey(AID_B, v) && v == Bytes{7});
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == BLK);
}

// Sync() pushes the staged delta to the base and clears the local overlay; later
// reads fall through to the base. Clearing is proven by mutating the base after.
BOOST_AUTO_TEST_CASE(sync_clears_overlay)
{
    CCoinsViewDB db{{.path = "overlay_sync", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache cache(&db);
    cache.SetBestBlock(BLK);
    cache.StageAssetPolicy(AID_A, Policy(4, 0x3));
    BOOST_CHECK(cache.Sync());

    AssetRegistryEntry p;
    BOOST_CHECK(db.ReadAssetPolicy(AID_A, p) && int(p.decimals) == 4);    // committed to base
    BOOST_CHECK(cache.ReadAssetPolicy(AID_A, p) && int(p.decimals) == 4); // read falls through to base

    db.EraseAssetPolicy(AID_A);                          // overlay cleared, so base change shows through
    BOOST_CHECK(!cache.ReadAssetPolicy(AID_A, p));
}

// A failing base BatchWrite must not silently drop the staged asset delta.
BOOST_AUTO_TEST_CASE(failed_flush_retains_delta)
{
    FailingBatchWriteView base;
    CCoinsViewCache cache(&base);
    cache.SetBestBlock(BLK);
    cache.StageAssetPolicy(AID_A, Policy(2, 0x2));

    BOOST_CHECK(!cache.Flush());                         // base rejects the write
    AssetRegistryEntry p;
    BOOST_CHECK(cache.ReadAssetPolicy(AID_A, p) && int(p.decimals) == 2); // delta retained
}

// A flush with only coin changes (no staged asset delta) still advances
// DB_ASSET_BEST_BLOCK to the coins best block, and writes no phantom asset data.
// Slice 5 relies on this invariant for non-asset blocks.
BOOST_AUTO_TEST_CASE(best_block_advances_without_asset_delta)
{
    CCoinsViewDB db{{.path = "overlay_nodelta", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache cache(&db);
    cache.SetBestBlock(BLK);

    const Txid txid = Txid::FromUint256(AID_A);
    cache.AddCoin(COutPoint{txid, 0}, Coin(CTxOut(1000, CScript()), 1, false), false);
    BOOST_CHECK(cache.Flush()); // no Stage* called -> cursor carries a null asset delta

    BOOST_CHECK(db.GetAssetRegistryBestBlock() == BLK);  // asset best tracks coins best
    AssetRegistryEntry p;
    BOOST_CHECK(!db.ReadAssetPolicy(AID_A, p));           // no phantom asset entries written
}

// Scalar-feed overlay (CFD_GENERALISATION.md §3, Slice 1b): per-epoch record and
// per-feed head each overlay independently — staged write beats base, erase masks
// base, distinct (asset,feed,epoch) keys are independent.
BOOST_AUTO_TEST_CASE(scalar_overlay)
{
    AssetBaseStub base;
    base.scalar[{AID_A, 1u, 5ull}] = ScalarRec(0x11);
    base.scalar_head[{AID_A, 1u}] = 5ull;
    CCoinsViewCache cache(&base);

    ScalarRecord got;
    BOOST_CHECK(cache.ReadAssetScalar(AID_A, 1, 5, got));      // base visible through cache
    BOOST_CHECK_EQUAL(int(got.scalar.begin()[0]), 0x11);
    uint64_t head = 0;
    BOOST_CHECK(cache.ReadAssetScalarHead(AID_A, 1, head));
    BOOST_CHECK_EQUAL(head, 5u);

    cache.StageAssetScalar(AID_A, 1, 6, ScalarRec(0x22, 9));   // staged per-epoch write beats base
    BOOST_CHECK(cache.ReadAssetScalar(AID_A, 1, 6, got));
    BOOST_CHECK_EQUAL(int(got.scalar.begin()[0]), 0x22);
    BOOST_CHECK_EQUAL(got.publication_height, 9);

    cache.StageAssetScalarHead(AID_A, 1, 6);                   // head advances in overlay
    BOOST_CHECK(cache.ReadAssetScalarHead(AID_A, 1, head));
    BOOST_CHECK_EQUAL(head, 6u);

    cache.StageEraseAssetScalar(AID_A, 1, 5);                  // erase masks base
    BOOST_CHECK(!cache.ReadAssetScalar(AID_A, 1, 5, got));

    BOOST_CHECK(!cache.ReadAssetScalar(AID_A, 2, 5, got));     // distinct feed_id independent...
    cache.StageAssetScalar(AID_A, 2, 0, ScalarRec(0x33));      // ...visible once staged
    BOOST_CHECK(cache.ReadAssetScalar(AID_A, 2, 0, got));
    BOOST_CHECK_EQUAL(int(got.scalar.begin()[0]), 0x33);

    cache.StageEraseAssetScalarHead(AID_A, 1);                 // head erase masks base
    BOOST_CHECK(!cache.ReadAssetScalarHead(AID_A, 1, head));
}

// Scalar publications + head commit to the backing CCoinsViewDB on Flush, atomic
// with DB_ASSET_BEST_BLOCK; a staged erase commits as a delete.
BOOST_AUTO_TEST_CASE(scalar_commit_to_db)
{
    CCoinsViewDB db{{.path = "overlay_scalar", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache cache(&db);
    cache.SetBestBlock(BLK);

    cache.StageAssetScalar(AID_A, 3, 10, ScalarRec(0x44, 100));
    cache.StageAssetScalarHead(AID_A, 3, 10);
    BOOST_CHECK(cache.Flush());

    ScalarRecord r;
    BOOST_CHECK(db.ReadAssetScalar(AID_A, 3, 10, r));
    BOOST_CHECK_EQUAL(int(r.scalar.begin()[0]), 0x44);
    BOOST_CHECK_EQUAL(r.publication_height, 100);
    BOOST_CHECK_EQUAL(r.scalar_format_id, assets::SCALAR_FORMAT_RAW_U256_LE);
    uint64_t head = 0;
    BOOST_CHECK(db.ReadAssetScalarHead(AID_A, 3, head));
    BOOST_CHECK_EQUAL(head, 10u);
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == BLK);  // asset best tracks coins best

    // A staged erase commits as a delete; asset best advances again.
    CCoinsViewCache cache2(&db);
    cache2.SetBestBlock(AID_B);
    cache2.StageEraseAssetScalar(AID_A, 3, 10);
    cache2.StageEraseAssetScalarHead(AID_A, 3);
    BOOST_CHECK(cache2.Flush());
    BOOST_CHECK(!db.ReadAssetScalar(AID_A, 3, 10, r));
    BOOST_CHECK(!db.ReadAssetScalarHead(AID_A, 3, head));
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == AID_B);
}

// Scalar child-cache merge: a child cache's staged scalar ops compose into the
// parent on flush (child supersedes), and the parent's flush carries them to DB.
BOOST_AUTO_TEST_CASE(scalar_nested_cache_merge)
{
    CCoinsViewDB db{{.path = "overlay_scalar_nested", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache parent(&db);
    CCoinsViewCache child(&parent);

    parent.StageAssetScalar(AID_A, 1, 5, ScalarRec(0x11));
    parent.StageAssetScalarHead(AID_A, 1, 5);
    child.StageAssetScalar(AID_A, 1, 5, ScalarRec(0x22, 42)); // child overwrites parent's epoch record
    child.StageAssetScalarHead(AID_A, 1, 6);                  // child advances the head
    child.StageAssetScalar(AID_B, 2, 0, ScalarRec(0x33));     // child adds a new feed

    ScalarRecord got;
    BOOST_CHECK(parent.ReadAssetScalar(AID_A, 1, 5, got) && int(got.scalar.begin()[0]) == 0x11); // pre-flush parent unaffected

    child.SetBestBlock(BLK);
    BOOST_CHECK(child.Flush()); // child -> parent

    BOOST_CHECK(parent.ReadAssetScalar(AID_A, 1, 5, got) && int(got.scalar.begin()[0]) == 0x22); // child composed in
    BOOST_CHECK_EQUAL(got.publication_height, 42);
    uint64_t head = 0;
    BOOST_CHECK(parent.ReadAssetScalarHead(AID_A, 1, head) && head == 6u);
    BOOST_CHECK(parent.ReadAssetScalar(AID_B, 2, 0, got) && int(got.scalar.begin()[0]) == 0x33);

    parent.SetBestBlock(BLK);
    BOOST_CHECK(parent.Flush()); // parent -> DB

    BOOST_CHECK(db.ReadAssetScalar(AID_A, 1, 5, got) && int(got.scalar.begin()[0]) == 0x22);
    BOOST_CHECK(db.ReadAssetScalarHead(AID_A, 1, head) && head == 6u);
    BOOST_CHECK(db.ReadAssetScalar(AID_B, 2, 0, got) && int(got.scalar.begin()[0]) == 0x33);
    BOOST_CHECK(db.GetAssetRegistryBestBlock() == BLK);
}

// Multiple same-feed publications in one block, then reverse-order disconnect
// (CFD_GENERALISATION.md §3.2, Slice 1d). This mirrors ConnectBlock's stage +
// undo-entry production and DisconnectBlock's reverse application, proving the head
// returns exactly to its pre-block state — and that a FORWARD apply would corrupt it.
BOOST_AUTO_TEST_CASE(scalar_multi_publication_reverse_undo)
{
    AssetBaseStub base; // feed (AID_A, 1) starts empty (no head)

    // Mirror ConnectBlock: read head through the view (sees prior staged epochs),
    // stage record + head, and record an undo entry capturing the prior head.
    auto publish = [](CCoinsViewCache& v, uint64_t epoch, unsigned char tag,
                      std::vector<CBlockUndo::ScalarUndoEntry>& undo) {
        uint64_t last = 0;
        const bool head_exists = v.ReadAssetScalarHead(AID_A, 1, last);
        v.StageAssetScalar(AID_A, 1, epoch, ScalarRec(tag, (int32_t)epoch));
        v.StageAssetScalarHead(AID_A, 1, epoch);
        CBlockUndo::ScalarUndoEntry e;
        e.asset_id = AID_A; e.feed_id = 1; e.epoch = epoch;
        e.had_prev_head = head_exists; e.prev_last_epoch = last;
        undo.push_back(e);
    };

    // --- reverse-order undo restores the exact pre-block state ---
    {
        CCoinsViewCache cache(&base);
        std::vector<CBlockUndo::ScalarUndoEntry> undo;
        publish(cache, 1, 0x11, undo);
        publish(cache, 2, 0x22, undo); // reads staged head=1 -> had_prev_head=true, prev=1

        uint64_t head = 0; ScalarRecord r;
        BOOST_CHECK(cache.ReadAssetScalarHead(AID_A, 1, head) && head == 2u);
        BOOST_CHECK(cache.ReadAssetScalar(AID_A, 1, 1, r) && cache.ReadAssetScalar(AID_A, 1, 2, r));

        for (auto it = undo.rbegin(); it != undo.rend(); ++it) { // reverse, like DisconnectBlock
            cache.StageEraseAssetScalar(it->asset_id, it->feed_id, it->epoch);
            if (it->had_prev_head) cache.StageAssetScalarHead(it->asset_id, it->feed_id, it->prev_last_epoch);
            else cache.StageEraseAssetScalarHead(it->asset_id, it->feed_id);
        }
        BOOST_CHECK(!cache.ReadAssetScalar(AID_A, 1, 1, r));
        BOOST_CHECK(!cache.ReadAssetScalar(AID_A, 1, 2, r));
        BOOST_CHECK(!cache.ReadAssetScalarHead(AID_A, 1, head)); // head gone -> exact pre-block state
    }

    // --- regression guard: FORWARD-order undo corrupts the head ---
    {
        CCoinsViewCache cache(&base);
        std::vector<CBlockUndo::ScalarUndoEntry> undo;
        publish(cache, 1, 0x11, undo);
        publish(cache, 2, 0x22, undo);

        for (auto it = undo.begin(); it != undo.end(); ++it) { // WRONG: forward
            cache.StageEraseAssetScalar(it->asset_id, it->feed_id, it->epoch);
            if (it->had_prev_head) cache.StageAssetScalarHead(it->asset_id, it->feed_id, it->prev_last_epoch);
            else cache.StageEraseAssetScalarHead(it->asset_id, it->feed_id);
        }
        // entry(epoch1, had_prev_head=false) erases head; THEN entry(epoch2, prev=1)
        // wrongly RESTORES head=1 -> a phantom head survives. This is the bug reverse
        // order prevents.
        uint64_t head = 0;
        BOOST_CHECK(cache.ReadAssetScalarHead(AID_A, 1, head));
        BOOST_CHECK_EQUAL(head, 1u);
    }
}

BOOST_AUTO_TEST_SUITE_END()
