// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Slice 6: mempool asset-registration overlay (scope: registration conflicts only). The mempool
// tracks asset registrations carried by UNCONFIRMED transactions so admission rejects duplicate
// registrations and ticker collisions against other in-mempool txs (matching ConnectBlock's
// same-block registration visibility). It deliberately does NOT admit would-be bond rotations of
// mempool-only assets (their bond rules can't be validated against unconfirmed state). The virtual
// CCoinsView asset accessors (used by transfer validation / CheckTxInputs) keep seeing ONLY the
// confirmed prior-block registry, preserving the one-confirmation transfer rule. The overlay is
// kept consistent with the confirmed registry: stale entries are evicted on block connect, and an
// RBF replacement of a registration is exempt from the conflict checks for the tx it replaces.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <kernel/mempool_removal_reason.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <validation.h>
#include <assets/registry.h>

#include <test/util/asset_utils.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(mempool_asset_tests)

// Mine a few empty blocks so the early coinbases are mature enough to spend via the mempool
// (spend height = tip+1 must be >= coinbase_height + COINBASE_MATURITY).
static void MatureCoinbases(TestChain100Setup& s)
{
    for (int i = 0; i < 3; ++i) s.CreateAndProcessBlock({}, CScript() << OP_TRUE);
}

// Registration-conflict overlay: an unconfirmed mempool registration is visible to the
// registration path (mempool index) but NOT to the virtual accessors (the transfer-validation
// path), and a second independent registration of the same asset is rejected.
BOOST_FIXTURE_TEST_CASE(mempool_asset_duplicate_registration, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 X; memset(X.data(), 0x61, X.size());

    // tx1 registers X (ticker "MPLA"); submit to mempool.
    CTxOut o1{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    o1.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPLA");
    CMutableTransaction tx1 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {o1}, /*submit=*/false);
    CTransactionRef tx1ref = MakeTransactionRef(tx1);
    const MempoolAcceptResult r1 = m_node.chainman->ProcessTransaction(tx1ref);
    BOOST_REQUIRE_MESSAGE(r1.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          "tx1 unexpectedly rejected: " + r1.m_state.GetRejectReason());

    // Overlay separation: the transfer path (virtual accessors) sees confirmed-only state (X and
    // its ticker absent), while the registration path (mempool index) sees them.
    {
        LOCK(cs_main);
        CCoinsViewMemPool view(&m_node.chainman->ActiveChainstate().CoinsTip(), *m_node.mempool);
        AssetRegistryEntry e;
        BOOST_CHECK(!view.ReadAssetPolicy(X, e));           // virtual: confirmed-only -> absent
        uint256 bound;
        BOOST_CHECK(!view.ReadTickerBinding("MPLA", bound)); // virtual: confirmed-only -> absent
    }
    {
        LOCK(m_node.mempool->cs);
        const auto mp = m_node.mempool->GetMempoolAssetReg(X);
        BOOST_REQUIRE(mp.has_value());
        BOOST_CHECK(mp->icu_outpoint == COutPoint(tx1ref->GetHash(), 0));
        const auto tb = m_node.mempool->GetMempoolTickerBinding("MPLA");
        BOOST_REQUIRE(tb.has_value());
        BOOST_CHECK(tb->first == X);
        BOOST_CHECK(tb->second == tx1ref->GetHash());
    }

    // tx2 independently re-registers X (spends a DIFFERENT coinbase, not X's ICU) -> duplicate.
    CTxOut o2{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    o2.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07);
    CMutableTransaction tx2 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(1)}, {COutPoint(m_coinbase_txns.at(1)->GetHash(), 0)},
        2, {coinbaseKey}, {o2}, /*submit=*/false);
    const MempoolAcceptResult r2 = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx2));
    BOOST_CHECK(r2.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(r2.m_state.GetRejectReason(), "asset-duplicate-registration");
}

// Two mempool txs binding the same ticker to different assets: the second is rejected.
BOOST_FIXTURE_TEST_CASE(mempool_asset_ticker_collision, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 A; memset(A.data(), 0x62, A.size());
    uint256 B; memset(B.data(), 0x63, B.size());

    CTxOut oa{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    oa.vExt = test_util::BuildV1IssuerReg(A, 0x01, 0x07, "MPCOLL");
    CMutableTransaction txa = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {oa}, /*submit=*/false);
    const MempoolAcceptResult ra = m_node.chainman->ProcessTransaction(MakeTransactionRef(txa));
    BOOST_REQUIRE_MESSAGE(ra.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          "txa unexpectedly rejected: " + ra.m_state.GetRejectReason());

    CTxOut ob{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    ob.vExt = test_util::BuildV1IssuerReg(B, 0x01, 0x07, "MPCOLL"); // same ticker, different asset
    CMutableTransaction txb = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(1)}, {COutPoint(m_coinbase_txns.at(1)->GetHash(), 0)},
        2, {coinbaseKey}, {ob}, /*submit=*/false);
    const MempoolAcceptResult rb = m_node.chainman->ProcessTransaction(MakeTransactionRef(txb));
    BOOST_CHECK(rb.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(rb.m_state.GetRejectReason(), "asset-ticker-duplicate");
}

// A would-be bond rotation of a MEMPOOL-ONLY asset (tx2 spends tx1's unconfirmed ICU and
// re-registers) is rejected at admission: we cannot validate rotation bond rules against
// unconfirmed state. Note this is NOT an RBF replacement (tx2 spends tx1's ICU output, not tx1's
// funding input), so the RBF exemption does not apply.
BOOST_FIXTURE_TEST_CASE(mempool_asset_unconfirmed_rotation_rejected, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 X; memset(X.data(), 0x65, X.size());
    const CScript bond_spk = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    CTxOut o1{(10 * COIN), bond_spk};
    o1.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPROT");
    CMutableTransaction tx1 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {o1}, /*submit=*/false);
    CTransactionRef tx1ref = MakeTransactionRef(tx1);
    const MempoolAcceptResult r1 = m_node.chainman->ProcessTransaction(tx1ref);
    BOOST_REQUIRE_MESSAGE(r1.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          "tx1 rejected: " + r1.m_state.GetRejectReason());

    CTxOut o2{(9 * COIN), bond_spk};
    o2.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPROT");
    CMutableTransaction tx2 = CreateValidMempoolTransaction(
        {tx1ref}, {COutPoint(tx1ref->GetHash(), 0)},
        1, {coinbaseKey}, {o2}, /*submit=*/false);
    const MempoolAcceptResult r2 = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx2));
    BOOST_CHECK(r2.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(r2.m_state.GetRejectReason(), "asset-duplicate-registration");
}

// Removing the registering tx from the mempool clears the overlay entry (asset + derived ticker).
BOOST_FIXTURE_TEST_CASE(mempool_asset_reg_index_cleared_on_removal, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 X; memset(X.data(), 0x64, X.size());

    CTxOut o1{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    o1.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPDROP");
    CMutableTransaction tx1 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {o1}, /*submit=*/false);
    CTransactionRef tx1ref = MakeTransactionRef(tx1);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(tx1ref).m_result_type == MempoolAcceptResult::ResultType::VALID);

    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(m_node.mempool->GetMempoolAssetReg(X).has_value());
        BOOST_CHECK(m_node.mempool->GetMempoolTickerBinding("MPDROP").has_value());
    }
    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*tx1ref, MemPoolRemovalReason::EXPIRY);
    }
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(!m_node.mempool->GetMempoolAssetReg(X).has_value());
        BOOST_CHECK(!m_node.mempool->GetMempoolTickerBinding("MPDROP").has_value());
    }
}

// HIGH-finding regression: a mempool registration the chain tip makes unmineable is evicted on
// block connect, so the overlay never masks the confirmed registry nor holds an unmineable tx.
// Covers both an asset becoming confirmed-registered and a ticker becoming confirmed-bound
// elsewhere, each via a DIFFERENT tx confirmed in a block (so no input conflict removes it).
BOOST_FIXTURE_TEST_CASE(mempool_asset_stale_reg_evicted_on_tip_change, TestChain100Setup)
{
    MatureCoinbases(*this);

    // --- asset staleness: mempool registers X; a block confirms X via a different tx ---
    uint256 X; memset(X.data(), 0x71, X.size());
    CTxOut mx{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    mx.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07);
    CMutableTransaction txm = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {mx}, /*submit=*/false);
    CTransactionRef txmref = MakeTransactionRef(txm);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(txmref).m_result_type == MempoolAcceptResult::ResultType::VALID);

    CTxOut bx{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    bx.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07);
    CMutableTransaction txb = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(1)}, {COutPoint(m_coinbase_txns.at(1)->GetHash(), 0)},
        2, {coinbaseKey}, {bx}, /*submit=*/false);
    CreateAndProcessBlock({txb}, CScript() << OP_TRUE); // confirms X via txb

    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(txmref->GetHash()))); // stale txm evicted
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(!m_node.mempool->GetMempoolAssetReg(X).has_value());
    }

    // --- ticker staleness: mempool binds T to A; a block confirms T -> B (different asset) ---
    uint256 A; memset(A.data(), 0x72, A.size());
    uint256 B; memset(B.data(), 0x73, B.size());
    CTxOut ma{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    ma.vExt = test_util::BuildV1IssuerReg(A, 0x01, 0x07, "MPSTL");
    CMutableTransaction txa = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(2)}, {COutPoint(m_coinbase_txns.at(2)->GetHash(), 0)},
        3, {coinbaseKey}, {ma}, /*submit=*/false);
    CTransactionRef txaref = MakeTransactionRef(txa);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(txaref).m_result_type == MempoolAcceptResult::ResultType::VALID);

    CTxOut bb{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    bb.vExt = test_util::BuildV1IssuerReg(B, 0x01, 0x07, "MPSTL");
    CMutableTransaction txbb = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(3)}, {COutPoint(m_coinbase_txns.at(3)->GetHash(), 0)},
        4, {coinbaseKey}, {bb}, /*submit=*/false);
    CreateAndProcessBlock({txbb}, CScript() << OP_TRUE); // confirms T -> B

    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(txaref->GetHash()))); // stale txa evicted
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(!m_node.mempool->GetMempoolTickerBinding("MPSTL").has_value()); // overlay cleared
    }
    {
        LOCK(cs_main);
        uint256 conf;
        // The confirmed binding (T -> B) is now authoritative, no longer masked by the stale entry.
        BOOST_CHECK(m_node.chainman->ActiveChainstate().CoinsTip().ReadTickerBinding("MPSTL", conf));
        BOOST_CHECK(conf == B);
    }
}

// MEDIUM-finding regression: a higher-fee RBF replacement of an unconfirmed asset registration is
// admitted (the registration it replaces is exempt from the duplicate/ticker checks), not rejected.
BOOST_FIXTURE_TEST_CASE(mempool_asset_registration_rbf_replacement, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 X; memset(X.data(), 0x74, X.size());

    // tx_m registers X / "MPRBF" with a 6-COIN bond (lower fee).
    CTxOut om{(6 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    om.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPRBF");
    CMutableTransaction txm = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {om}, /*submit=*/false);
    CTransactionRef txmref = MakeTransactionRef(txm);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(txmref).m_result_type == MempoolAcceptResult::ResultType::VALID);

    // tx_r replaces tx_m: SAME funding input (coinbase 0), same asset/ticker, higher fee (5-COIN bond).
    CTxOut orr{(5 * COIN), GetScriptForDestination(WitnessV0KeyHash(uint160()))};
    orr.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPRBF");
    CMutableTransaction txr = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {orr}, /*submit=*/false);
    CTransactionRef txrref = MakeTransactionRef(txr);
    const MempoolAcceptResult rr = m_node.chainman->ProcessTransaction(txrref);
    BOOST_REQUIRE_MESSAGE(rr.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          "RBF replacement unexpectedly rejected: " + rr.m_state.GetRejectReason());

    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(txmref->GetHash()))); // tx_m replaced
    BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(txrref->GetHash())));
    {
        LOCK(m_node.mempool->cs);
        const auto mp = m_node.mempool->GetMempoolAssetReg(X);
        BOOST_REQUIRE(mp.has_value());
        BOOST_CHECK(mp->txid == txrref->GetHash());          // index now owned by tx_r
        const auto tb = m_node.mempool->GetMempoolTickerBinding("MPRBF");
        BOOST_REQUIRE(tb.has_value());
        BOOST_CHECK(tb->second == txrref->GetHash());
    }
}

// PACKAGE-INTERNAL regression: a CPFP package where a LOW-FEE parent registration (fails alone as
// TX_RECONSIDERABLE, so it enters the multi-tx path instead of being accepted standalone) is
// fee-bumped by a child that re-registers the SAME asset / SAME ticker. This is the only case the
// conflict is invisible to both the confirmed registry and the mempool index, so it exercises the
// in-package overlay (m_subpackage.m_asset_regs). The package must reject and NEITHER tx may land
// in the mempool — the latter also proves the parent went through the package path (had it been
// accepted standalone, it would remain in the mempool and this assertion would fail).
//
// Helper context: MockMempoolMinFee raises the dynamic mempool-min above min-relay, opening the
// RECONSIDERABLE gap [min_relay.GetFee(size), GetMinFee.GetFee(size)) the parent fee sits in.
BOOST_FIXTURE_TEST_CASE(mempool_asset_package_cpfp_duplicate_registration, TestChain100Setup)
{
    MatureCoinbases(*this);
    MockMempoolMinFee(CFeeRate(5000)); // dynamic min 5000 sat/kvB > min-relay 1000 sat/kvB
    const CScript spk = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    uint256 X; memset(X.data(), 0x81, X.size());

    // Low-fee parent: registers X (bond) + a funding output for the child; fee = 700 sat.
    const CAmount parent_fee{700};
    CTxOut p_bond{(5 * COIN), spk}; p_bond.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07);
    CTxOut p_fund{(50 * COIN) - (5 * COIN) - parent_fee, spk};
    CMutableTransaction tx_parent = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {p_bond, p_fund}, /*submit=*/false);
    CTransactionRef parent_ref = MakeTransactionRef(tx_parent);

    // Confirm the parent sits in the RECONSIDERABLE gap (below dynamic min, at/above relay floor),
    // i.e. it will go through the multi-tx package path rather than being accepted standalone.
    const int64_t pvs = GetVirtualTransactionSize(*parent_ref);
    BOOST_REQUIRE(m_node.mempool->GetMinFee().GetFee(pvs) > parent_fee);
    BOOST_REQUIRE(m_node.mempool->m_opts.min_relay_feerate.GetFee(pvs) <= parent_fee);

    // High-fee child spends the parent's funding output (index 1) and re-registers X.
    CTxOut c_bond{(5 * COIN), spk}; c_bond.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07);
    CMutableTransaction tx_child = CreateValidMempoolTransaction(
        {parent_ref}, {COutPoint(parent_ref->GetHash(), 1)},
        101, {coinbaseKey}, {c_bond}, /*submit=*/false);
    CTransactionRef child_ref = MakeTransactionRef(tx_child);

    const auto res = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                       {parent_ref, child_ref}, /*test_accept=*/false, /*client_maxfeerate=*/{});
    BOOST_CHECK(res.m_state.IsInvalid());
    const auto it = res.m_tx_results.find(child_ref->GetWitnessHash());
    BOOST_REQUIRE(it != res.m_tx_results.end());
    BOOST_CHECK_EQUAL(it->second.m_state.GetRejectReason(), "asset-duplicate-registration");
    // Neither tx admitted (also proves the parent went via the package path, not standalone).
    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(parent_ref->GetHash())));
    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(child_ref->GetHash())));
}

// PACKAGE-INTERNAL regression (ticker variant): low-fee parent registers asset A / ticker T; child
// registers a DIFFERENT asset B with the SAME ticker T -> in-package ticker collision.
BOOST_FIXTURE_TEST_CASE(mempool_asset_package_cpfp_ticker_collision, TestChain100Setup)
{
    MatureCoinbases(*this);
    MockMempoolMinFee(CFeeRate(5000));
    const CScript spk = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    uint256 A; memset(A.data(), 0x82, A.size());
    uint256 B; memset(B.data(), 0x83, B.size());

    const CAmount parent_fee{700};
    CTxOut p_bond{(5 * COIN), spk}; p_bond.vExt = test_util::BuildV1IssuerReg(A, 0x01, 0x07, "MPCPK");
    CTxOut p_fund{(50 * COIN) - (5 * COIN) - parent_fee, spk};
    CMutableTransaction tx_parent = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {p_bond, p_fund}, /*submit=*/false);
    CTransactionRef parent_ref = MakeTransactionRef(tx_parent);

    const int64_t pvs = GetVirtualTransactionSize(*parent_ref);
    BOOST_REQUIRE(m_node.mempool->GetMinFee().GetFee(pvs) > parent_fee);
    BOOST_REQUIRE(m_node.mempool->m_opts.min_relay_feerate.GetFee(pvs) <= parent_fee);

    CTxOut c_bond{(5 * COIN), spk}; c_bond.vExt = test_util::BuildV1IssuerReg(B, 0x01, 0x07, "MPCPK");
    CMutableTransaction tx_child = CreateValidMempoolTransaction(
        {parent_ref}, {COutPoint(parent_ref->GetHash(), 1)},
        101, {coinbaseKey}, {c_bond}, /*submit=*/false);
    CTransactionRef child_ref = MakeTransactionRef(tx_child);

    const auto res = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                       {parent_ref, child_ref}, /*test_accept=*/false, /*client_maxfeerate=*/{});
    BOOST_CHECK(res.m_state.IsInvalid());
    const auto it = res.m_tx_results.find(child_ref->GetWitnessHash());
    BOOST_REQUIRE(it != res.m_tx_results.end());
    BOOST_CHECK_EQUAL(it->second.m_state.GetRejectReason(), "asset-ticker-duplicate");
    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(parent_ref->GetHash())));
    BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(child_ref->GetHash())));
}

// Pre-unlock rotation mirror (ICU_CHILD.md §5.3): the mempool must compare a successor bond
// against the registry's rotation_min_sats (95% of the initial bond, locked until unlock), NOT
// the previous ICU value. A CONFIRMED 5-COIN registration has rotation_min_sats = 4.75 COIN; a
// rotation down to exactly 4.75 COIN is valid in a block and must also be accepted by the
// mempool. The previous mirror compared against the prior 5-COIN value and wrongly rejected it.
BOOST_FIXTURE_TEST_CASE(mempool_pre_unlock_rotation_mirror, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 X; memset(X.data(), 0x90, X.size());
    const CScript bond_spk = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    // Confirm an initial 5-COIN registration so its registry entry (rotation_min_sats = 4.75
    // COIN) is authoritative in the confirmed view.
    CTxOut o1{(5 * COIN), bond_spk};
    o1.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPMIR");
    CMutableTransaction tx1 = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {o1}, /*submit=*/false);
    CTransactionRef tx1ref = MakeTransactionRef(tx1);
    CreateAndProcessBlock({tx1}, CScript() << OP_TRUE);
    const CAmount rot_min = (5 * COIN * 95) / 100; // 4.75 COIN
    {
        LOCK(cs_main);
        AssetRegistryEntry e;
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().ReadAssetPolicy(X, e));
        BOOST_CHECK_EQUAL(e.rotation_min_sats, (uint64_t)rot_min);
    }

    // Reject a rotation just below rotation_min_sats first (stays out of the mempool, so it
    // leaves no input conflict for the accept case that follows).
    CTxOut o_lo{rot_min - 1, bond_spk};
    o_lo.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPMIR");
    CMutableTransaction tx_lo = CreateValidMempoolTransaction(
        {tx1ref}, {COutPoint(tx1ref->GetHash(), 0)},
        2, {coinbaseKey}, {o_lo}, /*submit=*/false);
    const MempoolAcceptResult r_lo = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx_lo));
    BOOST_CHECK(r_lo.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(r_lo.m_state.GetRejectReason(), "asset-bond-decrease");

    // Accept a rotation down to exactly rotation_min_sats.
    CTxOut o_ok{rot_min, bond_spk};
    o_ok.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPMIR");
    CMutableTransaction tx_ok = CreateValidMempoolTransaction(
        {tx1ref}, {COutPoint(tx1ref->GetHash(), 0)},
        2, {coinbaseKey}, {o_ok}, /*submit=*/false);
    const MempoolAcceptResult r_ok = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx_ok));
    BOOST_CHECK_MESSAGE(r_ok.m_result_type == MempoolAcceptResult::ResultType::VALID,
                        "pre-unlock rotation to rotation_min_sats rejected: " + r_ok.m_state.GetRejectReason());
}

// Mempool mirror of root-sponsored child registration (ICU_CHILD.md §3, §5.3): a child ticker
// ROOT.SUFFIX may register at the low child floor (10,000 sats) when the parent root's CURRENT
// ICU is co-spent at full bond. Below the floor is rejected.
BOOST_FIXTURE_TEST_CASE(mempool_child_sponsorship_accept_and_floor, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 ROOT; memset(ROOT.data(), 0xA1, ROOT.size());
    uint256 CHILD; memset(CHILD.data(), 0xA2, CHILD.size());
    const CScript bond_spk = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    // Confirm a full-bond root "ACME".
    CTxOut oroot{(5 * COIN), bond_spk};
    oroot.vExt = test_util::BuildV1IssuerReg(ROOT, 0x01, 0x07, "ACME");
    CMutableTransaction txroot = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {oroot}, /*submit=*/false);
    CTransactionRef txrootref = MakeTransactionRef(txroot);
    CreateAndProcessBlock({txroot}, CScript() << OP_TRUE);

    // A child-registration tx co-spends the confirmed root ICU + a coinbase for funding, and
    // recreates the root successor (vout0) alongside the child (vout1).
    auto build_child = [&](CAmount child_bond, int cb_index) {
        CTxOut succ{(5 * COIN), bond_spk};
        succ.vExt = test_util::BuildV1IssuerReg(ROOT, 0x01, 0x07, "ACME");
        CTxOut child{child_bond, bond_spk};
        child.vExt = test_util::BuildV1IssuerReg(CHILD, 0x01, 0x07, "ACME.CHILD");
        return CreateValidMempoolTransaction(
            {txrootref, m_coinbase_txns.at(cb_index)},
            {COutPoint(txrootref->GetHash(), 0), COutPoint(m_coinbase_txns.at(cb_index)->GetHash(), 0)},
            2, {coinbaseKey}, {succ, child}, /*submit=*/false);
    };

    // Below the child floor (9,999 sats) -> rejected even with valid parent sponsorship.
    {
        CMutableTransaction tx = build_child(9'999, 1);
        const MempoolAcceptResult r = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        BOOST_CHECK(r.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(r.m_state.GetRejectReason(), "asset-bond-minimum");
    }

    // At the child floor (10,000 sats) with parent co-spend -> accepted.
    {
        CMutableTransaction tx = build_child(10'000, 1);
        const MempoolAcceptResult r = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        BOOST_CHECK_MESSAGE(r.m_result_type == MempoolAcceptResult::ResultType::VALID,
                            "sponsored child at floor rejected: " + r.m_state.GetRejectReason());
    }
}

// Policy (stricter than consensus by design): a transaction may not carry two initial
// IssuerRegs for the SAME new asset. ConnectBlock would accept it (treating outs.back() as
// authoritative); relay rejects it so the registry is unambiguous (ICU_CHILD.md §5.3).
BOOST_FIXTURE_TEST_CASE(mempool_asset_multiple_initial_reg_rejected, TestChain100Setup)
{
    MatureCoinbases(*this);
    uint256 X; memset(X.data(), 0xB1, X.size());
    const CScript spk = GetScriptForDestination(WitnessV0KeyHash(uint160()));
    CTxOut o0{(5 * COIN), spk}; o0.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07, "MPDUP");
    CTxOut o1{(5 * COIN), spk}; o1.vExt = test_util::BuildV1IssuerReg(X, 0x01, 0x07);
    CMutableTransaction tx = CreateValidMempoolTransaction(
        {m_coinbase_txns.at(0)}, {COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        1, {coinbaseKey}, {o0, o1}, /*submit=*/false);
    const MempoolAcceptResult r = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
    BOOST_CHECK(r.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(r.m_state.GetRejectReason(), "asset-multiple-initial-reg");
}

BOOST_AUTO_TEST_SUITE_END()
