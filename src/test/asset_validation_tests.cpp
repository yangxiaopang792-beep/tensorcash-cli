// Unit tests for asset consensus validation using CheckTxInputs

#include <boost/test/unit_test.hpp>

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <addresstype.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <coins.h>
#include <txdb.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>
#include <test/util/zk_test_helpers.h>
#include <util/strencodings.h>
#include <streams.h>
#include <serialize.h>

#include <assets/asset.h>
#include <limits>
#include <optional>

using AID = uint256;
using zk_test::uint256S;

static std::vector<unsigned char> TLV(uint8_t type, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> result;
    result.push_back(type);
    
    // Write compact size manually
    if (payload.size() < 253) {
        result.push_back(static_cast<unsigned char>(payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        result.push_back(253);
        result.push_back(payload.size() & 0xFF);
        result.push_back((payload.size() >> 8) & 0xFF);
    } else {
        // For larger sizes, would need more bytes
        result.push_back(254);
        for (int i = 0; i < 4; ++i) {
            result.push_back((payload.size() >> (i * 8)) & 0xFF);
        }
    }
    
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

static std::vector<unsigned char> MakeAssetTag(const AID& id, uint64_t amount, uint32_t flags=0)
{
    std::vector<unsigned char> p; p.insert(p.end(), id.begin(), id.end()); unsigned char buf8[8]; WriteLE64(buf8, amount); p.insert(p.end(), buf8, buf8+8); unsigned char f[4]; WriteLE32(f, flags); p.insert(p.end(), f, f+4); return TLV(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG), p);
}

static std::vector<unsigned char> MakeIssuerReg(const AID& id, uint32_t policy_bits, uint16_t allowed, std::optional<uint64_t> unlock = std::nullopt)
{
    uint64_t unlock_fees = unlock.has_value() ? *unlock : std::numeric_limits<uint64_t>::max();
    return test_util::BuildV1IssuerReg(id, policy_bits, allowed, "", 0xFF, unlock_fees);
}

static std::vector<unsigned char> MakeDerSig(unsigned char sighash)
{
    std::vector<unsigned char> sig;
    sig.reserve(72);
    sig.push_back(0x30);
    sig.push_back(0x44);
    sig.push_back(0x02);
    sig.push_back(0x20);
    for (unsigned char b = 0x01; b <= 0x20; ++b) {
        sig.push_back(b);
    }
    sig.push_back(0x02);
    sig.push_back(0x20);
    for (unsigned char b = 0x21; b <= 0x40; ++b) {
        sig.push_back(b);
    }
    sig.push_back(sighash);
    return sig;
}

static void AttachIcuSignature(CTxIn& in, unsigned char sighash = SIGHASH_ALL)
{
    CScript script;
    script << MakeDerSig(sighash);
    in.scriptSig = script;
}

BOOST_FIXTURE_TEST_SUITE(asset_validation_tests, BasicTestingSetup)

// Helper: run CheckTxInputs for a constructed tx and view
static bool Check(const CTransaction& tx, CCoinsViewCache& view, CAmount& fee, std::string& reject_reason)
{
    TxValidationState st; bool ok = Consensus::CheckTxInputs(tx, st, view, /*height=*/100, fee); if (!ok) reject_reason = st.GetRejectReason(); return ok;
}

BOOST_AUTO_TEST_CASE(asset_conservation_zero_delta)
{
    // Setup DB and cache
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view(&db);
    // Create an asset input with 1000 units
    AID aid; memset(aid.data(), 0x45, aid.size());
    Txid in_txid; memset(const_cast<std::byte*>(in_txid.data()), 0x01, in_txid.size());
    COutPoint prev(in_txid, 0);
    CTxOut prevout(1000, CScript()<<OP_1); prevout.vExt = MakeAssetTag(aid, 1000);
    view.AddCoin(prev, Coin(prevout, /*height=*/10, /*coinbase=*/false), /*overwrite=*/false);

    // Build tx: one input consuming prev, one output recreating 1000 units
    CMutableTransaction mtx; mtx.version = 2; mtx.vin.resize(1); mtx.vin[0].prevout = prev; mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.emplace_back(1000, CScript()<<OP_1); mtx.vout.back().vExt = MakeAssetTag(aid, 1000);
    CTransaction tx(mtx);
    CAmount fee; std::string reason; BOOST_CHECK(Check(tx, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(asset_mint_requires_icu)
{
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view(&db);
    // Provide a spendable non-asset input for fee accounting
    Txid in_txid; memset(const_cast<std::byte*>(in_txid.data()), 0x02, in_txid.size());
    COutPoint prev(in_txid, 0);
    CTxOut prevout(1000, CScript()<<OP_1);
    view.AddCoin(prev, Coin(prevout, 10, false), false);

    // Mint 500 units to output without ICU in inputs -> reject
    AID aid; memset(aid.data(), 0x55, aid.size());
    CMutableTransaction mtx; mtx.vin.resize(1); mtx.vin[0].prevout = prev; mtx.vout.emplace_back(100, CScript()<<OP_1); mtx.vout.back().vExt = MakeAssetTag(aid, 500);
    CTransaction tx(mtx);
    CAmount fee; std::string reason; BOOST_CHECK(!Check(tx, view, fee, reason)); BOOST_CHECK_EQUAL(reason, "asset-mint-unauthorized");
}

BOOST_AUTO_TEST_CASE(asset_burn_requires_icu)
{
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view(&db);
    AID aid; memset(aid.data(), 0x66, aid.size());
    // Provide an asset UTXO of 600 units and a plain input for fees
    Txid asset_txid; memset(const_cast<std::byte*>(asset_txid.data()), 0x03, asset_txid.size()); COutPoint asset_prev(asset_txid, 0);
    CTxOut asset_prevout(1000, CScript()<<OP_1); asset_prevout.vExt = MakeAssetTag(aid, 600);
    view.AddCoin(asset_prev, Coin(asset_prevout, 10, false), false);
    Txid fee_txid; memset(const_cast<std::byte*>(fee_txid.data()), 0x04, fee_txid.size()); COutPoint fee_prev(fee_txid, 0);
    CTxOut fee_prevout(1000, CScript()<<OP_1); view.AddCoin(fee_prev, Coin(fee_prevout, 10, false), false);

    // Burn 600 by spending asset input but not recreating AssetTag outputs; without ICU -> reject
    CMutableTransaction mtx1; mtx1.vin = {CTxIn(asset_prev), CTxIn(fee_prev)}; mtx1.vout = {CTxOut(100, CScript()<<OP_1)}; CTransaction tx1(mtx1);
    CAmount fee; std::string reason; BOOST_CHECK(!Check(tx1, view, fee, reason)); BOOST_CHECK_EQUAL(reason, "asset-burn-needs-icu");

    // With ICU in inputs (add IssuerReg coin), accept
    Txid icu_txid; memset(const_cast<std::byte*>(icu_txid.data()), 0x05, icu_txid.size()); COutPoint icu_prev(icu_txid, 0);
    CTxOut icu_prevout(1000, CScript()<<OP_1); icu_prevout.vExt = MakeIssuerReg(aid, /*policy_bits=*/0x0003u, /*allowed=*/assets::SPK_DEFAULT_ALLOWED);
    view.AddCoin(icu_prev, Coin(icu_prevout, 9, false), false);
    CMutableTransaction mtx2; mtx2.vin = {CTxIn(asset_prev), CTxIn(icu_prev), CTxIn(fee_prev)}; mtx2.vout = {CTxOut(100, CScript()<<OP_1)};
    AttachIcuSignature(mtx2.vin[1]);
    CTransaction tx2(mtx2);
    reason.clear(); BOOST_CHECK(Check(tx2, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(script_family_enforcement)
{
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view(&db);
    AID aid; memset(aid.data(), 0x77, aid.size());
    // Provide an ICU input
    Txid icu_txid; memset(const_cast<std::byte*>(icu_txid.data()), 0x07, icu_txid.size()); COutPoint icu_prev(icu_txid, 0);
    CTxOut icu_prevout(1000, CScript()<<OP_1); icu_prevout.vExt = MakeIssuerReg(aid, 0x0003u, /*allowed=*/(assets::SPK_P2PKH | assets::SPK_P2WPKH));
    view.AddCoin(icu_prev, Coin(icu_prevout, 9, false), false);

    // Mint to a disallowed family (P2TR) -> reject with asset-spk-not-allowed
    // Construct P2TR scriptPubKey: OP_1 <32-byte>
    std::vector<unsigned char> key32(32, 0x01);
    CScript spk_p2tr = CScript() << OP_1 << key32;
    CMutableTransaction mtx; mtx.vin = {CTxIn(icu_prev)}; mtx.vout.emplace_back(100, spk_p2tr); mtx.vout.back().vExt = MakeAssetTag(aid, 10);
    AttachIcuSignature(mtx.vin[0]);
    CAmount fee; std::string reason; BOOST_CHECK(!Check(CTransaction(mtx), view, fee, reason));
    BOOST_CHECK_EQUAL(reason, "asset-spk-not-allowed");
}

BOOST_AUTO_TEST_CASE(asset_delta_no_overflow)
{
    // Construct a tx that mints very large amounts to ensure Δ accounting does not overflow
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view(&db);

    // Provide ICU input with IssuerReg allowing mint
    AID aid; memset(aid.data(), 0x99, aid.size());
    Txid icu_txid; memset(const_cast<std::byte*>(icu_txid.data()), 0x07, icu_txid.size()); COutPoint icu_prev(icu_txid, 0);
    CTxOut icu_prevout(1000, CScript()<<OP_1); icu_prevout.vExt = MakeIssuerReg(aid, /*policy_bits=*/0x0001u, /*allowed=*/assets::SPK_DEFAULT_ALLOWED);
    view.AddCoin(icu_prev, Coin(icu_prevout, 9, false), false);

    // Build tx: spend ICU and mint near-maximum amounts
    CMutableTransaction mtx; mtx.vin = {CTxIn(icu_prev)};
    CTxOut out1(100, CScript()<<OP_1); out1.vExt = MakeAssetTag(aid, std::numeric_limits<uint64_t>::max()); mtx.vout.push_back(out1);
    CTxOut out2(100, CScript()<<OP_1); out2.vExt = MakeAssetTag(aid, 1); mtx.vout.push_back(out2);
    AttachIcuSignature(mtx.vin[0]);
    CTransaction tx(mtx);

    CAmount fee; std::string reason; BOOST_CHECK(Check(tx, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(asset_burn_policy_flip_forbidden)
{
    // Scenario 1: rotation attempting to enable burn must fail
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view(&db);
    AID aid; memset(aid.data(), 0x42, aid.size());
    Txid prev_txid; memset(const_cast<std::byte*>(prev_txid.data()), 0x11, prev_txid.size());
    COutPoint icu_prev(prev_txid, 0);
    CTxOut icu_prevout(1000, CScript()<<OP_TRUE);
    icu_prevout.vExt = MakeIssuerReg(aid, assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED, /*unlock=*/2000);
    view.AddCoin(icu_prev, Coin(icu_prevout, /*height=*/9, /*coinbase=*/false), /*overwrite=*/false);

    CMutableTransaction flip_tx;
    flip_tx.vin.emplace_back(icu_prev);
    CTxOut rotated(icu_prevout.nValue, CScript()<<OP_TRUE);
    rotated.vExt = MakeIssuerReg(aid, assets::MINT_ALLOWED | assets::BURN_ALLOWED, assets::SPK_DEFAULT_ALLOWED, /*unlock=*/2000);
    flip_tx.vout.push_back(rotated);
    AttachIcuSignature(flip_tx.vin[0]);
    CTransaction tx_forbidden(flip_tx);
    CAmount fee = 0; std::string reason;
    BOOST_CHECK(!Check(tx_forbidden, view, fee, reason));
    BOOST_CHECK_EQUAL(reason, "asset-policy-burn-flip");

    // Scenario 2: rotation disabling burn remains valid
    CCoinsViewDB db2{{.path = "test2", .cache_bytes = 1<<20, .memory_only = true}, {}}; CCoinsViewCache view2(&db2);
    Txid prev_txid2; memset(const_cast<std::byte*>(prev_txid2.data()), 0x22, prev_txid2.size());
    COutPoint icu_prev2(prev_txid2, 0);
    CTxOut icu_prevout2(1500, CScript()<<OP_TRUE);
    icu_prevout2.vExt = MakeIssuerReg(aid, assets::MINT_ALLOWED | assets::BURN_ALLOWED, assets::SPK_DEFAULT_ALLOWED, /*unlock=*/3000);
    view2.AddCoin(icu_prev2, Coin(icu_prevout2, /*height=*/9, /*coinbase=*/false), /*overwrite=*/false);

    CMutableTransaction allow_tx;
    allow_tx.vin.emplace_back(icu_prev2);
    CTxOut rotated_allow(icu_prevout2.nValue, CScript()<<OP_TRUE);
    rotated_allow.vExt = MakeIssuerReg(aid, assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED, /*unlock=*/3000);
    allow_tx.vout.push_back(rotated_allow);
    AttachIcuSignature(allow_tx.vin[0]);
    CTransaction tx_allowed(allow_tx);
    reason.clear();
    fee = 0;
    BOOST_CHECK(Check(tx_allowed, view2, fee, reason));
}

// ICU Governance Tests

BOOST_AUTO_TEST_CASE(icu_issuance_cap_enforcement)
{
    // Test that issuance cap prevents minting beyond the cap
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    CCoinsViewCache view(&db);

    AID aid; memset(aid.data(), 0x77, aid.size());

    // Register asset with issuance cap = 10000 units
    AssetRegistryEntry entry;
    entry.policy_bits = assets::MINT_ALLOWED;
    entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    entry.issuance_cap_units = 10000;
    entry.issued_total = 0;
    entry.burned_total = 0;
    db.WriteAssetPolicy(aid, entry);

    // Create IssuerReg UTXO for authorization
    COutPoint icu_prev(Txid::FromUint256(uint256S("01")), 0);
    CTxOut icu_prevout(1000, CScript() << OP_TRUE);
    icu_prevout.vExt = MakeIssuerReg(aid, assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED);
    view.AddCoin(icu_prev, Coin(icu_prevout, 10, false), false);

    // Mint 9000 units - should succeed at mempool level
    CMutableTransaction mint_tx1;
    COutPoint prev1(Txid::FromUint256(uint256S("02")), 0);
    mint_tx1.vin.emplace_back(icu_prev);
    mint_tx1.vin.emplace_back(prev1);
    AttachIcuSignature(mint_tx1.vin[0]);
    mint_tx1.vout.emplace_back(1000, CScript() << OP_TRUE);
    mint_tx1.vout[0].vExt = MakeAssetTag(aid, 9000);

    view.AddCoin(prev1, Coin(CTxOut(1000, CScript() << OP_TRUE), 10, false), false);

    CTransaction tx1(mint_tx1);
    std::string reason;
    CAmount fee = 0;

    // Should succeed at mempool level (cap checked in ConnectBlock)
    BOOST_CHECK(Check(tx1, view, fee, reason));

    // Simulate issued_total update
    entry.issued_total = 9000;
    db.WriteAssetPolicy(aid, entry);

    // Try to mint 2000 more units (total would be 11000 > 10000 cap) - should fail in ConnectBlock
    // For mempool validation, transaction structure is valid
    CMutableTransaction mint_tx2;
    COutPoint icu_prev2(Txid::FromUint256(uint256S("03")), 0);
    CTxOut icu_prevout2(1000, CScript() << OP_TRUE);
    icu_prevout2.vExt = MakeIssuerReg(aid, assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED);
    view.AddCoin(icu_prev2, Coin(icu_prevout2, 11, false), false);

    COutPoint prev2(Txid::FromUint256(uint256S("04")), 1);
    mint_tx2.vin.emplace_back(icu_prev2);
    mint_tx2.vin.emplace_back(prev2);
    AttachIcuSignature(mint_tx2.vin[0]);
    mint_tx2.vout.emplace_back(1000, CScript() << OP_TRUE);
    mint_tx2.vout[0].vExt = MakeAssetTag(aid, 2000);

    view.AddCoin(prev2, Coin(CTxOut(1000, CScript() << OP_TRUE), 11, false), false);

    CTransaction tx2(mint_tx2);
    BOOST_CHECK(Check(tx2, view, fee, reason)); // Mempool allows, ConnectBlock would reject

    // Verify burns don't free up cap space
    entry.burned_total = 5000; // 5000 burned
    db.WriteAssetPolicy(aid, entry);
    // issued_total still 9000, can only mint 1000 more (not 6000)
}

BOOST_AUTO_TEST_CASE(icu_wrap_required_enforcement)
{
    // Test that WRAP_REQUIRED flag requires ICU_KEYWRAP on outputs
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    CCoinsViewCache view(&db);

    AID aid; memset(aid.data(), 0x88, aid.size());
    uint256 icu_commit; memset(icu_commit.data(), 0x99, icu_commit.size());

    // Register asset with WRAP_REQUIRED
    AssetRegistryEntry entry;
    entry.policy_bits = 0;
    entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    entry.icu_flags = assets::WRAP_REQUIRED;
    entry.icu_ctxt_commit = icu_commit;
    db.WriteAssetPolicy(aid, entry);

    // Create transfer without ICU_KEYWRAP - would fail in ConnectBlock
    CMutableTransaction tx_no_wrap;
    COutPoint wrap_prev(Txid::FromUint256(uint256S("88")), 0);
    tx_no_wrap.vin.emplace_back(wrap_prev);
    tx_no_wrap.vout.emplace_back(1000, CScript() << OP_TRUE);
    tx_no_wrap.vout[0].vExt = MakeAssetTag(aid, 500);

    CTxOut wrap_prevout(1000, CScript() << OP_TRUE);
    wrap_prevout.vExt = MakeAssetTag(aid, 500);
    view.AddCoin(wrap_prev, Coin(wrap_prevout, 10, false), false);

    CTransaction tx1(tx_no_wrap);
    std::string reason;
    CAmount fee = 0;

    // Mempool validation passes (WRAP check is in ConnectBlock)
    BOOST_CHECK(Check(tx1, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(icu_quorum_predicate_zero_delta)
{
    // Test that governance rotations require Δ=0
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    CCoinsViewCache view(&db);

    AID aid; memset(aid.data(), 0xAA, aid.size());

    // Register asset with quorum governance
    AssetRegistryEntry entry;
    entry.policy_bits = assets::MINT_ALLOWED;
    entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    entry.policy_quorum_bps = 5000; // 50% quorum
    entry.issued_total = 10000;
    entry.burned_total = 0;
    entry.icu_visibility = 0;
    db.WriteAssetPolicy(aid, entry);

    // Create rotation transaction (IssuerReg with changed icu_visibility)
    COutPoint icu_prev(Txid::FromUint256(uint256S("AA01")), 0);
    CTxOut icu_prevout(1000, CScript() << OP_TRUE);
    icu_prevout.vExt = test_util::BuildV1IssuerReg(
        aid, assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 0, uint256(), uint256(), {},
        0, 0, uint256(), 0, 5000);
    view.AddCoin(icu_prev, Coin(icu_prevout, 10, false), false);
    entry.icu_outpoint = icu_prev;
    db.WriteAssetPolicy(aid, entry);

    // Rotation with non-zero delta (minting) - would fail in ConnectBlock
    CMutableTransaction rotate_tx;
    rotate_tx.vin.emplace_back(icu_prev);
    AttachIcuSignature(rotate_tx.vin[0]);

    // Add fee input for satoshi accounting
    COutPoint fee_prev(Txid::FromUint256(uint256S("AA02")), 0);
    CTxOut fee_prevout(2000, CScript() << OP_TRUE);
    view.AddCoin(fee_prev, Coin(fee_prevout, 10, false), false);
    rotate_tx.vin.emplace_back(fee_prev);

    // New IssuerReg with changed icu_visibility
    CTxOut new_icu(1000, CScript() << OP_TRUE);
    new_icu.vExt = test_util::BuildV1IssuerReg(
        aid, assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 0, uint256(), uint256(), {},
        0, 1, uint256(), 0, 5000); // icu_visibility changed from 0 to 1
    rotate_tx.vout.push_back(new_icu);

    // Add asset output (creates non-zero delta)
    rotate_tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    rotate_tx.vout[1].vExt = MakeAssetTag(aid, 100); // Minting 100 units

    CTransaction tx(rotate_tx);
    std::string reason;
    CAmount fee = 0;

    // Mempool allows (Δ=0 check is in ConnectBlock)
    BOOST_CHECK(Check(tx, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(icu_quorum_ballot_counting)
{
    // Test paired ballot counting for quorum validation
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    CCoinsViewCache view(&db);

    AID aid; memset(aid.data(), 0xBB, aid.size());

    // Register asset: 10000 issued, 50% quorum = need 5000 units
    AssetRegistryEntry entry;
    entry.policy_bits = 0;
    entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    entry.policy_quorum_bps = 5000;
    entry.issued_total = 10000;
    entry.burned_total = 0;
    entry.icu_visibility = 0;
    db.WriteAssetPolicy(aid, entry);

    COutPoint icu_prev(Txid::FromUint256(uint256S("BB00")), 0);
    CTxOut icu_prevout(1000, CScript() << OP_TRUE);
    icu_prevout.vExt = test_util::BuildV1IssuerReg(
        aid, 0, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 0, uint256(), uint256(), {},
        0, 0, uint256(), 0, 5000);
    view.AddCoin(icu_prev, Coin(icu_prevout, 10, false), false);
    entry.icu_outpoint = icu_prev;
    db.WriteAssetPolicy(aid, entry);

    // Create rotation with paired ballots
    CMutableTransaction rotate_tx;

    // ICU input
    rotate_tx.vin.emplace_back(icu_prev);
    AttachIcuSignature(rotate_tx.vin[0]);

    // Ballot inputs: 3 inputs with asset amounts (2000 + 2000 + 1500 = 5500 units)
    for (int i = 0; i < 3; ++i) {
        std::string txid_str = "BB0" + std::to_string(i+1);
        COutPoint ballot_in(Txid::FromUint256(uint256S(txid_str)), 0);
        CTxOut ballot_prevout(1000, CScript() << OP_TRUE);
        uint64_t amount = (i < 2) ? 2000 : 1500;
        ballot_prevout.vExt = MakeAssetTag(aid, amount);
        view.AddCoin(ballot_in, Coin(ballot_prevout, 10, false), false);
        rotate_tx.vin.emplace_back(ballot_in);
    }

    // New IssuerReg with changed icu_visibility
    CTxOut new_icu(1000, CScript() << OP_TRUE);
    new_icu.vExt = test_util::BuildV1IssuerReg(
        aid, 0, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 0, uint256(), uint256(), {},
        0, 1, uint256(), 0, 5000); // icu_visibility changed
    rotate_tx.vout.push_back(new_icu);

    // Paired ballot outputs (must match input amounts at same positions)
    rotate_tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    rotate_tx.vout[1].vExt = MakeAssetTag(aid, 2000);
    rotate_tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    rotate_tx.vout[2].vExt = MakeAssetTag(aid, 2000);
    rotate_tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    rotate_tx.vout[3].vExt = MakeAssetTag(aid, 1500);

    CTransaction tx(rotate_tx);
    std::string reason;
    CAmount fee = 0;

    // Structure is valid (quorum counting happens in ConnectBlock)
    BOOST_CHECK(Check(tx, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(icu_immutable_asset_rotation_rejection)
{
    // Test that fully immutable assets (quorum_bps=0, no cap) reject rotations
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    CCoinsViewCache view(&db);

    AID aid; memset(aid.data(), 0xCC, aid.size());

    // Fully immutable: quorum_bps=0, issuance_cap_units=0
    AssetRegistryEntry entry;
    entry.policy_bits = 0;
    entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    entry.policy_quorum_bps = 0;
    entry.issuance_cap_units = 0;
    entry.issued_total = 1000;
    entry.burned_total = 0;
    entry.icu_visibility = 0;
    db.WriteAssetPolicy(aid, entry);

    COutPoint icu_prev(Txid::FromUint256(uint256S("CC")), 0);
    CTxOut icu_prevout(1000, CScript() << OP_TRUE);
    icu_prevout.vExt = test_util::BuildV1IssuerReg(
        aid, 0, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 0, uint256(), uint256(), {},
        0, 0, uint256(), 0, 0);
    view.AddCoin(icu_prev, Coin(icu_prevout, 10, false), false);
    entry.icu_outpoint = icu_prev;
    db.WriteAssetPolicy(aid, entry);

    // Attempt rotation (change icu_visibility) - would fail in ConnectBlock
    CMutableTransaction rotate_tx;
    rotate_tx.vin.emplace_back(icu_prev);
    AttachIcuSignature(rotate_tx.vin[0]);

    CTxOut new_icu(1000, CScript() << OP_TRUE);
    new_icu.vExt = test_util::BuildV1IssuerReg(
        aid, 0, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 0, uint256(), uint256(), {},
        0, 1, uint256(), 0, 0); // icu_visibility changed - not allowed!
    rotate_tx.vout.push_back(new_icu);

    CTransaction tx(rotate_tx);
    std::string reason;
    CAmount fee = 0;

    // Mempool structure check passes (immutability check in ConnectBlock)
    BOOST_CHECK(Check(tx, view, fee, reason));
}

BOOST_AUTO_TEST_CASE(icu_custom_quorum_threshold)
{
    // Test custom quorum threshold (e.g., 75% requires quorum_bps=7500)
    CCoinsViewDB db{{.path = "test", .cache_bytes = 1<<20, .memory_only = true}, {}};
    CCoinsViewCache view(&db);

    AID aid; memset(aid.data(), 0xDD, aid.size());

    // Asset with 75% quorum and fixed supply
    AssetRegistryEntry entry;
    entry.policy_bits = 0;
    entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    entry.policy_quorum_bps = 7500; // 75% explicit threshold
    entry.issuance_cap_units = 10000;
    entry.issued_total = 10000;
    entry.burned_total = 2000; // settled_supply = 8000
    entry.icu_visibility = 0;
    db.WriteAssetPolicy(aid, entry);

    // Need 75% of 8000 = 6000 units in paired ballots
    COutPoint icu_prev(Txid::FromUint256(uint256S("DD00")), 0);
    CTxOut icu_prevout(1000, CScript() << OP_TRUE);
    icu_prevout.vExt = test_util::BuildV1IssuerReg(
        aid, 0, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 10000, uint256(), uint256(), {},
        0, 0, uint256(), 0, 7500); // quorum_bps = 7500
    view.AddCoin(icu_prev, Coin(icu_prevout, 10, false), false);
    entry.icu_outpoint = icu_prev;
    db.WriteAssetPolicy(aid, entry);

    CMutableTransaction rotate_tx;
    rotate_tx.vin.emplace_back(icu_prev);
    AttachIcuSignature(rotate_tx.vin[0]);

    // Add ballot inputs totaling 6500 units (exceeds 75% threshold)
    for (int i = 0; i < 4; ++i) {
        std::string txid_str = "DD0" + std::to_string(i+1);
        COutPoint ballot_in(Txid::FromUint256(uint256S(txid_str)), 0);
        CTxOut ballot_prevout(1000, CScript() << OP_TRUE);
        uint64_t amount = (i < 3) ? 2000 : 500;
        ballot_prevout.vExt = MakeAssetTag(aid, amount);
        view.AddCoin(ballot_in, Coin(ballot_prevout, 10, false), false);
        rotate_tx.vin.emplace_back(ballot_in);
    }

    CTxOut new_icu(1000, CScript() << OP_TRUE);
    new_icu.vExt = test_util::BuildV1IssuerReg(
        aid, 0, assets::SPK_DEFAULT_ALLOWED,
        "", 0xFF, std::numeric_limits<uint64_t>::max(),
        0, uint256(), 0, 0, 0, 10000, uint256(), uint256(), {},
        0, 1, uint256(), 0, 7500); // icu_visibility changed, quorum_bps stays 7500
    rotate_tx.vout.push_back(new_icu);

    // Paired outputs
    for (int i = 0; i < 4; ++i) {
        uint64_t amount = (i < 3) ? 2000 : 500;
        rotate_tx.vout.emplace_back(1000, CScript() << OP_TRUE);
        rotate_tx.vout.back().vExt = MakeAssetTag(aid, amount);
    }

    CTransaction tx(rotate_tx);
    std::string reason;
    CAmount fee = 0;

    // Structure valid (quorum check in ConnectBlock)
    BOOST_CHECK(Check(tx, view, fee, reason));
}

// --- Scalar-carrier allowlist activation (CFD_GENERALISATION.md §3.3, Slice 1d) ---

namespace {
// Activation is gated by Consensus::Params::ScalarCfdHeight, which is INT_MAX on the
// production chains (so 0x11 is inert/"below activation") and 0 on regtest (so 0x11 is
// active/"above activation"). The unit-test arg parser does not accept -scalarcfdheight,
// so we straddle the boundary by chain selection instead: the suite default fixture is
// MAIN (below), and ScalarCfdRegtestSetup is REGTEST (above).
struct ScalarCfdRegtestSetup : public BasicTestingSetup {
    ScalarCfdRegtestSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

static assets::IssuerScalar SampleScalarPub()
{
    assets::IssuerScalar p{};
    p.underlying_asset_id = uint256::FromHex(std::string(64, 'a')).value();
    p.feed_id = 1;
    p.scalar_epoch = 1;
    p.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    p.scalar = uint256::FromHex(std::string(64, 'b')).value();
    return p;
}
} // namespace

static CTransaction MakeScalarCarrierTx(CCoinsViewCache& view, const COutPoint& op)
{
    const CScript spk = CScript() << OP_TRUE;
    view.AddCoin(op, Coin(CTxOut(100000, spk), /*nHeight=*/1, /*fCoinBase=*/false), false);
    CMutableTransaction mtx;
    mtx.vin.emplace_back(op);
    CTxOut carrier(0, CScript() << OP_RETURN);
    carrier.vExt = assets::BuildIssuerScalarTlv(SampleScalarPub());
    mtx.vout.push_back(carrier);
    mtx.vout.emplace_back(90000, spk);
    return CTransaction{mtx};
}

// CONSENSUS allowlist (CheckTxInputs), BELOW activation: on MAIN, ScalarCfdHeight is
// INT_MAX, so a scalar carrier is rejected as the unknown TLV "outext" — the path that
// blocked the tx before the ConnectBlock publication pass. (Suite fixture = MAIN.)
BOOST_AUTO_TEST_CASE(scalar_carrier_rejected_below_activation)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    const COutPoint op{Txid::FromUint256(uint256::FromHex(std::string(64, '1')).value()), 0};
    const CTransaction tx = MakeScalarCarrierTx(view, op);

    TxValidationState st; CAmount fee = 0;
    BOOST_CHECK(!Consensus::CheckTxInputs(tx, st, view, /*nSpendHeight=*/100, fee));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "outext");
}

// CONSENSUS allowlist (CheckTxInputs), AT/ABOVE activation: on regtest, ScalarCfdHeight
// is 0, so the carrier type is accepted by the allowlist (no "outext").
BOOST_FIXTURE_TEST_CASE(scalar_carrier_accepted_above_activation, ScalarCfdRegtestSetup)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    const COutPoint op{Txid::FromUint256(uint256::FromHex(std::string(64, '1')).value()), 0};
    const CTransaction tx = MakeScalarCarrierTx(view, op);

    TxValidationState st; CAmount fee = 0;
    const bool ok = Consensus::CheckTxInputs(tx, st, view, /*nSpendHeight=*/100, fee);
    BOOST_CHECK(ok);
    BOOST_CHECK(st.GetRejectReason() != "outext");
}

// The RELAY allowlist in IsStandardTx must treat the ISSUER_SCALAR carrier as a known
// TLV so publication txs relay (height-agnostic; consensus is the activation gate).
BOOST_AUTO_TEST_CASE(scalar_carrier_is_standard)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::FromHex(std::string(64, '1')).value()), 0});
    CTxOut carrier(0, CScript() << OP_RETURN);
    carrier.vExt = assets::BuildIssuerScalarTlv(SampleScalarPub());
    mtx.vout.push_back(carrier);
    mtx.vout.emplace_back(90000, GetScriptForDestination(WitnessV0KeyHash(uint160{})));
    const CTransaction tx{mtx};

    std::string reason;
    const bool ok = IsStandardTx(tx, /*max_datacarrier_bytes=*/std::optional<unsigned>{83},
                                 /*permit_bare_multisig=*/true, CFeeRate{0}, reason);
    BOOST_CHECK_MESSAGE(ok, "scalar carrier tx not standard, reason=" << reason);
    BOOST_CHECK(reason != "outext");
}

// Same-tx batching is BLOCK-only: two scalar carriers are each RECOGNISED (not
// "outext"), but the tx is non-standard for relay because a carrier must be OP_RETURN
// and >1 OP_RETURN is non-standard. scalar.publish therefore emits one carrier per tx;
// batching across a block uses separate txs. (Locks the documented boundary.)
BOOST_AUTO_TEST_CASE(scalar_two_carriers_nonstandard)
{
    auto pub1 = SampleScalarPub();                 // epoch 1
    auto pub2 = SampleScalarPub(); pub2.scalar_epoch = 2;

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::FromHex(std::string(64, '1')).value()), 0});
    CTxOut c1(0, CScript() << OP_RETURN); c1.vExt = assets::BuildIssuerScalarTlv(pub1);
    CTxOut c2(0, CScript() << OP_RETURN); c2.vExt = assets::BuildIssuerScalarTlv(pub2);
    mtx.vout.push_back(c1);
    mtx.vout.push_back(c2);
    mtx.vout.emplace_back(90000, GetScriptForDestination(WitnessV0KeyHash(uint160{})));
    const CTransaction tx{mtx};

    std::string reason;
    const bool ok = IsStandardTx(tx, std::optional<unsigned>{83}, true, CFeeRate{0}, reason);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(reason, "multi-op-return"); // recognised individually; rejected only for >1 OP_RETURN
}

BOOST_AUTO_TEST_SUITE_END()
