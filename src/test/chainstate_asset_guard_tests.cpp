// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Startup recovery-guard tests for the asset registry. These exercise the
// pre-ReplayBlocks() guard in node::CompleteChainstateInitialization()
// (src/node/chainstate.cpp). The guard REFUSES to start on an interrupted asset
// update marker (1) or an asset_best/coins_best divergence (3), and STARTS in the
// clean / pre-activation cases. An interrupted coins flush/reorg spanning asset-active
// blocks (2) no longer hard-stops: asset mutations now commit atomically with the UTXO
// best-block, so ReplayBlocks() rolls the registry forward/back in lockstep with the
// coins and recovers it from block data — exercised here by the faithful
// interrupted-rollback and reindex parity cases below.
//
// Strategy: build an on-disk chainstate, flush, tear the ChainstateManager
// down to release the LevelDB locks, optionally corrupt the raw chainstate
// markers to simulate an interrupted/mismatched shutdown, recreate the manager
// (mirroring SimulateNodeRestart in validation_chainstatemanager_tests.cpp) and
// re-run LoadChainstate(), asserting on the returned ChainstateLoadStatus.

#include <node/chainstate.h>

#include <assets/registry.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <dbwrapper.h>
#include <kernel/chainstatemanager_opts.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <test/util/asset_utils.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <optional>
#include <vector>

namespace {

// These mirror the (file-static) key bytes in src/txdb.cpp. Kept in sync by
// hand; a mismatch would make the guard read different keys than we write here.
constexpr uint8_t DB_BEST_BLOCK{'B'};
constexpr uint8_t DB_HEAD_BLOCKS{'H'};
constexpr uint8_t DB_ASSET_BEST_BLOCK{'A'};
constexpr uint8_t DB_ASSET_HEAD_BLOCKS{'a'};

// On-disk chainstate so markers persist across the manager teardown/reload.
TestOpts AssetGuardOpts()
{
    return TestOpts{
        .coins_db_in_memory = false,
        .block_tree_db_in_memory = false,
    };
}

// Flush, tear down the manager, optionally corrupt the on-disk chainstate
// markers, recreate the manager (so the block index is reloaded from disk) and
// re-run the load path under test. Returns the load status.
node::ChainstateLoadStatus ReloadChainstate(ChainTestingSetup& setup,
                                            const std::function<void(CDBWrapper&)>& inject = {})
{
    auto& node = setup.m_node;
    const fs::path datadir{setup.m_args.GetDataDirNet()};

    {
        LOCK(::cs_main);
        for (Chainstate* cs : node.chainman->GetAll()) cs->ForceFlushStateToDisk();
    }
    node.validation_signals->SyncWithValidationInterfaceQueue();

    // Release the chainstate LevelDB locks before touching the DB directly.
    {
        LOCK(::cs_main);
        node.chainman->ResetChainstates();
    }
    node.chainman.reset();

    if (inject) {
        CDBWrapper db{DBParams{
            .path = datadir / "chainstate",
            .cache_bytes = size_t{1} << 20,
            .memory_only = false,
            .wipe_data = false,
            .obfuscate = true, // coins DB is obfuscated (InitCoinsDB)
        }};
        inject(db);
    }

    // Recreate the manager (mirrors SimulateNodeRestart) so the block index is
    // reloaded from disk and LookupBlockIndex() works inside the guard.
    node.notifications = std::make_unique<node::KernelNotifications>(
        Assert(node.shutdown_request), node.exit_status, *Assert(node.warnings));
    const ChainstateManager::Options chainman_opts{
        .chainparams = ::Params(),
        .datadir = datadir,
        .notifications = *node.notifications,
        .signals = node.validation_signals.get(),
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = setup.m_args.GetBlocksDirPath(),
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = datadir / "blocks" / "index",
            .cache_bytes = setup.m_kernel_cache_sizes.block_tree_db,
            .memory_only = false,
        },
    };
    node.chainman = std::make_unique<ChainstateManager>(*Assert(node.shutdown_signal), chainman_opts, blockman_opts);

    node::ChainstateLoadOptions options;
    options.mempool = node.mempool.get();
    options.coins_db_in_memory = false;
    options.wipe_chainstate_db = false;
    options.prune = false;
    auto [status, error] = node::LoadChainstate(*node.chainman, setup.m_kernel_cache_sizes, options);
    return status;
}

// Reindex the chainstate: tear the manager down, WIPE the coins + asset-registry
// LevelDB (wipe_chainstate_db=true, exactly what -reindex-chainstate does), reload an
// empty chainstate, and reconnect every block from the on-disk block files. This drives
// the same RollforwardBlock -> ConnectBlock asset-staging path that crash recovery's
// ReplayBlocks() uses, but from a guaranteed-empty registry, so it proves the asset
// registry is fully re-derivable from block data alone. The wipe path also bypasses the
// startup guard (it is gated on !wipe_chainstate_db), so this needs no guard relaxation.
void ReindexChainstate(ChainTestingSetup& setup)
{
    auto& node = setup.m_node;
    const fs::path datadir{setup.m_args.GetDataDirNet()};

    {
        LOCK(::cs_main);
        for (Chainstate* cs : node.chainman->GetAll()) cs->ForceFlushStateToDisk();
    }
    node.validation_signals->SyncWithValidationInterfaceQueue();

    {
        LOCK(::cs_main);
        node.chainman->ResetChainstates();
    }
    node.chainman.reset();

    node.notifications = std::make_unique<node::KernelNotifications>(
        Assert(node.shutdown_request), node.exit_status, *Assert(node.warnings));
    const ChainstateManager::Options chainman_opts{
        .chainparams = ::Params(),
        .datadir = datadir,
        .notifications = *node.notifications,
        .signals = node.validation_signals.get(),
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = setup.m_args.GetBlocksDirPath(),
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = datadir / "blocks" / "index",
            .cache_bytes = setup.m_kernel_cache_sizes.block_tree_db,
            .memory_only = false,
        },
    };
    node.chainman = std::make_unique<ChainstateManager>(*Assert(node.shutdown_signal), chainman_opts, blockman_opts);

    node::ChainstateLoadOptions options;
    options.mempool = node.mempool.get();
    options.coins_db_in_memory = false;
    options.wipe_chainstate_db = true; // REINDEX: wipe coins + asset registry
    options.prune = false;
    auto [status, error] = node::LoadChainstate(*node.chainman, setup.m_kernel_cache_sizes, options);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);

    // Reconnect every block from disk, rebuilding both the UTXO set and the asset
    // registry from scratch (what init does after a -reindex-chainstate wipe).
    BlockValidationState state;
    BOOST_REQUIRE(node.chainman->ActiveChainstate().ActivateBestChain(state, nullptr));
}

// Serialize an asset's policy entry ('R') and its ticker binding ('T') to bytes (nullopt
// if the policy is absent), for bit-for-bit comparison across a rebuild/reorg. These are
// the two asset key families a bare IssuerReg populates; the ICU-payload ('I') and zk-VK
// ('Z') families require an ICU payload / zk proof respectively and are not exercised by
// these IssuerReg-only fixtures, so they are out of scope for this dump.
std::optional<std::vector<std::byte>> DumpAsset(Chainstate& chainstate, const uint256& aid, const std::string& ticker)
{
    LOCK(::cs_main);
    AssetRegistryEntry e;
    if (!chainstate.CoinsTip().ReadAssetPolicy(aid, e)) return std::nullopt;
    DataStream ss;
    ss << e;
    uint256 bound;
    const bool has_ticker = !ticker.empty() && chainstate.CoinsTip().ReadTickerBinding(ticker, bound);
    ss << static_cast<uint8_t>(has_ticker ? 1 : 0);
    if (has_ticker) ss << bound;
    return std::vector<std::byte>(ss.begin(), ss.end());
}

// Default activation height is 0, so the whole 100-block TestChain100Setup chain
// is past activation and its tip carries an asset_best marker.
struct AssetActiveSetup : public TestChain100Setup {
    AssetActiveSetup() : TestChain100Setup{ChainType::REGTEST, AssetGuardOpts()} {}
};

// Genesis-only chain (tip height 0): no transactions are connected and no asset
// marker is ever written, regardless of activation height.
struct GenesisOnlySetup : public TestingSetup {
    GenesisOnlySetup() : TestingSetup{ChainType::REGTEST, AssetGuardOpts()} {}
};

} // namespace

BOOST_AUTO_TEST_SUITE(chainstate_asset_guard_tests)

// (a) Clean coins + matching asset_best → starts.
BOOST_FIXTURE_TEST_CASE(clean_matching_starts, AssetActiveSetup)
{
    BOOST_CHECK(ReloadChainstate(*this) == node::ChainstateLoadStatus::SUCCESS);
}

// (b) Clean coins + missing asset_best past activation → refuse.
BOOST_FIXTURE_TEST_CASE(missing_asset_best_past_activation_fails, AssetActiveSetup)
{
    const auto status = ReloadChainstate(*this, [](CDBWrapper& db) {
        db.Erase(DB_ASSET_BEST_BLOCK);   // drop 'A'
        db.Erase(DB_ASSET_HEAD_BLOCKS);  // ensure no 'a' (so guard (1) does not pre-empt)
    });
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
}

// (c) Clean coins + mismatched asset_best → refuse.
BOOST_FIXTURE_TEST_CASE(mismatched_asset_best_fails, AssetActiveSetup)
{
    const auto status = ReloadChainstate(*this, [](CDBWrapper& db) {
        db.Write(DB_ASSET_BEST_BLOCK, uint256::ONE); // 'A' != coins best
        db.Erase(DB_ASSET_HEAD_BLOCKS);
    });
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
}

// (d) Interrupted asset registry update (asset_heads marker present) → refuse.
BOOST_FIXTURE_TEST_CASE(interrupted_asset_update_fails, AssetActiveSetup)
{
    const auto status = ReloadChainstate(*this, [](CDBWrapper& db) {
        db.Write(DB_ASSET_HEAD_BLOCKS, std::vector<uint256>{uint256::ONE, uint256::ZERO}); // 'a'
        db.Erase(DB_ASSET_BEST_BLOCK);
    });
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
}

// (e) Interrupted rollback spanning asset-active blocks now STARTS and self-heals via
// replay (the Phase-0 hard-stop on this case was relaxed in 5c: asset mutations commit
// atomically with the UTXO best-block, so ReplayBlocks() rolls the registry back in
// lockstep with the coins rather than double-applying).
//
// Faithful interrupted-rollback simulation: we connect two asset-registering blocks 101
// (assetA / "ROLLA") and 102 (assetB / "ROLLB") on top of the height-100 fixture and
// flush them durably, so the on-disk DB GENUINELY holds the height-102 UTXO set and
// registry. We then erase DB_BEST_BLOCK and write heads = [new=100, old=102] — exactly
// the marker a node would leave if it crashed midway through a rollback from 102 to 100.
// ReplayBlocks() disconnects 102 then 101, reverting BOTH the coins and the staged asset
// registry. We assert the recovered DB is COHERENT at height 100 (not merely a logical
// tip): the registrations are gone, a UTXO created in 101 is removed, a UTXO spent in 101
// is restored, and asset_best == coins_best. A regression re-adding the hard-stop (or
// breaking std::any_of over BOTH heads — heads[1]=102 is asset-active) flips status back
// to FAILURE and is caught.
BOOST_FIXTURE_TEST_CASE(interrupted_rollback_spanning_asset_active_recovers, AssetActiveSetup)
{
    uint256 assetA; memset(assetA.data(), 0x71, assetA.size());
    uint256 assetB; memset(assetB.data(), 0x72, assetB.size());

    // Block 101 registers assetA/"ROLLA" (spends mature coinbase 0).
    CTxOut oA{(5 * COIN), CScript() << OP_TRUE};
    oA.vExt = test_util::BuildV1IssuerReg(assetA, 0x01, 0x07, "ROLLA");
    CMutableTransaction tA = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {oA}, /*submit=*/false);
    CBlock block101 = CreateAndProcessBlock({tA}, CScript() << OP_TRUE);

    // Block 102 registers assetB/"ROLLB" (spends mature coinbase 1).
    CTxOut oB{(5 * COIN), CScript() << OP_TRUE};
    oB.vExt = test_util::BuildV1IssuerReg(assetB, 0x02, 0x0F, "ROLLB");
    CMutableTransaction tB = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(1)}, {COutPoint(m_coinbase_txns.at(1)->GetHash(), 0)},
        1, {coinbaseKey}, {oB}, /*submit=*/false);
    CreateAndProcessBlock({tB}, CScript() << OP_TRUE);

    // UTXO probes: an output created in 101, and the input it spent (restored on rollback).
    const COutPoint created_in_101{block101.vtx.at(1)->GetHash(), 0};
    const COutPoint spent_by_101{m_coinbase_txns.at(0)->GetHash(), 0};

    uint256 h100, h102;
    {
        LOCK(::cs_main);
        const CChain& chain = m_node.chainman->ActiveChain();
        BOOST_REQUIRE_EQUAL(chain.Height(), 102);
        h100 = chain[100]->GetBlockHash();
        h102 = chain.Tip()->GetBlockHash();
        // Pre-crash sanity: both registrations live, created UTXO present, spent input gone.
        Chainstate& cs = m_node.chainman->ActiveChainstate();
        AssetRegistryEntry e;
        BOOST_REQUIRE(cs.CoinsTip().ReadAssetPolicy(assetA, e));
        BOOST_REQUIRE(cs.CoinsTip().ReadAssetPolicy(assetB, e));
        BOOST_REQUIRE(cs.CoinsTip().HaveCoin(created_in_101));
        BOOST_REQUIRE(!cs.CoinsTip().HaveCoin(spent_by_101));
    }

    // Crash midway through a rollback 102 -> 100: DB genuinely at 102, markers say
    // "rolling back old=102 to new=100".
    const auto status = ReloadChainstate(*this, [&](CDBWrapper& db) {
        db.Erase(DB_BEST_BLOCK);                                        // mid-flush: 'B' absent
        db.Write(DB_HEAD_BLOCKS, std::vector<uint256>{h100, h102});     // 'H' = [new=100, old=102]
    });

    // Guard no longer refuses; ReplayBlocks() completes the rollback to a COHERENT 100.
    BOOST_CHECK(status == node::ChainstateLoadStatus::SUCCESS);
    {
        LOCK(::cs_main);
        Chainstate& cs = m_node.chainman->ActiveChainstate();
        BOOST_CHECK_EQUAL(cs.m_chain.Tip()->nHeight, 100);
        BOOST_CHECK(cs.m_chain.Tip()->GetBlockHash() == h100);

        AssetRegistryEntry e;
        uint256 bound;
        // Registry: both registrations and their ticker bindings are reverted.
        BOOST_CHECK(!cs.CoinsTip().ReadAssetPolicy(assetA, e));
        BOOST_CHECK(!cs.CoinsTip().ReadAssetPolicy(assetB, e));
        BOOST_CHECK(!cs.CoinsTip().ReadTickerBinding("ROLLA", bound));
        BOOST_CHECK(!cs.CoinsTip().ReadTickerBinding("ROLLB", bound));
        // UTXO set is coherently at height 100: 101's created output is gone and the input
        // it spent is restored (proves the coins were genuinely rolled back, not just the
        // logical tip moved).
        BOOST_CHECK(!cs.CoinsTip().HaveCoin(created_in_101));
        BOOST_CHECK(cs.CoinsTip().HaveCoin(spent_by_101));
        // Atomic commit: asset_best tracks coins_best after the replay flush.
        BOOST_CHECK(cs.CoinsDB().GetAssetRegistryBestBlock() == cs.CoinsTip().GetBestBlock());
    }
}

// (f) Genesis-only chain (height 0) with no asset_best marker → starts.
// Exercises the genesis exemption (best_height > 0) so a fresh/pre-activation
// node is never stranded.
BOOST_FIXTURE_TEST_CASE(genesis_only_no_marker_starts, GenesisOnlySetup)
{
    const auto status = ReloadChainstate(*this, [](CDBWrapper& db) {
        db.Erase(DB_ASSET_BEST_BLOCK);
        db.Erase(DB_ASSET_HEAD_BLOCKS);
    });
    BOOST_CHECK(status == node::ChainstateLoadStatus::SUCCESS);
}

// (g) Crash/replay parity (reindex form): register assets, wipe the chainstate, and
// rebuild it by reconnecting every block from disk. The recovered asset policy + ticker
// entries must be byte-identical to the original, and asset_best must track coins_best —
// proving the registry is deterministically re-derivable from block data via ConnectBlock,
// which is exactly what makes ReplayBlocks() crash recovery safe. (Parity is checked for
// the policy 'R' and ticker 'T' families that an IssuerReg populates; the ICU-payload and
// zk-VK families are out of scope for this IssuerReg-only fixture — see DumpAsset.)
BOOST_FIXTURE_TEST_CASE(reindex_rebuilds_asset_registry_bit_for_bit, AssetActiveSetup)
{
    uint256 a1; memset(a1.data(), 0x55, a1.size());
    uint256 a2; memset(a2.data(), 0x66, a2.size());

    // Register a1/"RIDXA" (spends mature coinbase 0).
    CTxOut o1{(5 * COIN), CScript() << OP_TRUE};
    o1.vExt = test_util::BuildV1IssuerReg(a1, 0x01, 0x07, "RIDXA");
    CMutableTransaction t1 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {o1}, /*submit=*/false);
    CreateAndProcessBlock({t1}, CScript() << OP_TRUE);

    // Register a2/"RIDXB" (spends mature coinbase 1).
    CTxOut o2{(5 * COIN), CScript() << OP_TRUE};
    o2.vExt = test_util::BuildV1IssuerReg(a2, 0x02, 0x0F, "RIDXB");
    CMutableTransaction t2 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(1)}, {COutPoint(m_coinbase_txns.at(1)->GetHash(), 0)},
        1, {coinbaseKey}, {o2}, /*submit=*/false);
    CreateAndProcessBlock({t2}, CScript() << OP_TRUE);

    const auto baseline1 = DumpAsset(m_node.chainman->ActiveChainstate(), a1, "RIDXA");
    const auto baseline2 = DumpAsset(m_node.chainman->ActiveChainstate(), a2, "RIDXB");
    BOOST_REQUIRE(baseline1.has_value());
    BOOST_REQUIRE(baseline2.has_value());

    // Wipe + rebuild from block files.
    ReindexChainstate(*this);

    Chainstate& cs = m_node.chainman->ActiveChainstate();
    const auto rebuilt1 = DumpAsset(cs, a1, "RIDXA");
    const auto rebuilt2 = DumpAsset(cs, a2, "RIDXB");
    BOOST_REQUIRE(rebuilt1.has_value());
    BOOST_REQUIRE(rebuilt2.has_value());
    BOOST_CHECK(rebuilt1 == baseline1);
    BOOST_CHECK(rebuilt2 == baseline2);

    // The atomic commit keeps asset_best == coins_best after the rebuild flush.
    {
        LOCK(::cs_main);
        cs.ForceFlushStateToDisk();
        BOOST_CHECK(cs.CoinsDB().GetAssetRegistryBestBlock() == cs.CoinsTip().GetBestBlock());
    }
}

BOOST_AUTO_TEST_SUITE_END()
