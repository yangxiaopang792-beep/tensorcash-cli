// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Slice 5e-3 — wallet persistence for scalar note pairs: ScalarNotePairRecord serializes round-trip, a
// registered pair survives a wallet reload (Write -> LoadWallet -> Find/List), and the integrity gate
// (ValidateScalarNotePairRecord) rejects every way a record can mismatch its terms. Mirrors
// option_series_wallet_tests (DBKeys::SCALAR_NOTE_PAIR{"scalarnotepair"}).

#include <wallet/scalar_note_pair.h>

#include <assets/asset.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/transaction_identifier.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <tuple>
#include <vector>

using namespace wallet;

namespace {

uint256 Filled(unsigned char b) { uint256 u; std::fill(u.begin(), u.end(), b); return u; }

ScalarNotePairTerms MakeTerms()
{
    ScalarNotePairTerms t;
    t.descriptor_version = kScalarNotePairDescriptorVersion;
    t.source_type   = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
    t.payoff_mode   = static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE);
    t.loss_direction = 0x00;
    t.underlying_asset_id = Filled(0xA1);
    t.feed_id = 7;
    t.fixing_ref = 123456789ULL;
    t.publication_deadline_height = 150000;
    t.settle_lock_height = 150100;
    t.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    t.strike = Filled(0x64);
    t.fallback_scalar = Filled(0x5F);
    t.lambda_q = 218453;
    t.collateral_asset_id = Filled(0xC0);
    t.vault_im = 1'000'000;
    t.lot_count = 3;
    t.series_salt = Filled(0xEE);
    std::tie(t.long_token_id, t.short_token_id) = DeriveScalarNotePairTokenIds(t);
    return t;
}

ScalarNotePairRecord MakeRecord()
{
    ScalarNotePairRecord rec;
    rec.terms = MakeTerms();
    rec.pair_id = ComputeScalarNotePairId(rec.terms);
    const Txid issue = Txid::FromUint256(uint256::ONE);
    rec.issue_txid = uint256::ONE;
    rec.register_long_txid = Filled(0x33);
    rec.register_short_txid = Filled(0x33); // single batch registration tx covers both children
    rec.long_icu_outpoint = COutPoint(issue, 0);
    rec.short_icu_outpoint = COutPoint(issue, 1);
    rec.lot_vaults = {COutPoint(issue, 2), COutPoint(issue, 3), COutPoint(issue, 4)}; // == lot_count
    return rec;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(scalar_note_pair_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(record_serialization_roundtrip)
{
    const ScalarNotePairRecord rec = MakeRecord();
    DataStream ss{};
    ss << rec;
    ScalarNotePairRecord back;
    ss >> back;

    BOOST_CHECK(back.pair_id == rec.pair_id);
    BOOST_CHECK(back.long_icu_outpoint == rec.long_icu_outpoint);
    BOOST_CHECK(back.short_icu_outpoint == rec.short_icu_outpoint);
    BOOST_CHECK(back.register_long_txid == rec.register_long_txid);
    BOOST_CHECK(back.register_short_txid == rec.register_short_txid);
    BOOST_CHECK(back.issue_txid == rec.issue_txid);
    BOOST_CHECK(back.lot_vaults == rec.lot_vaults);
    BOOST_CHECK(back.terms.long_token_id == rec.terms.long_token_id);
    BOOST_CHECK(back.terms.short_token_id == rec.terms.short_token_id);
    BOOST_CHECK_EQUAL(back.terms.lot_count, rec.terms.lot_count);
    BOOST_CHECK_EQUAL(back.terms.vault_im, rec.terms.vault_im);
    // The deserialized terms must still hash to the same pair_id (no field drift).
    BOOST_CHECK(ComputeScalarNotePairId(back.terms) == rec.pair_id);
}

BOOST_AUTO_TEST_CASE(db_persistence_roundtrip)
{
    const ScalarNotePairRecord rec = MakeRecord();
    m_wallet.RegisterScalarNotePair(rec); // in-memory + WalletBatch write-through
    BOOST_REQUIRE(m_wallet.FindScalarNotePair(rec.pair_id).has_value());

    std::unique_ptr<WalletDatabase> db = DuplicateMockDatabase(m_wallet.GetDatabase());
    CWallet reloaded(m_node.chain.get(), "", std::move(db));
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);

    const auto found = reloaded.FindScalarNotePair(rec.pair_id);
    BOOST_REQUIRE(found.has_value());
    BOOST_CHECK(found->pair_id == rec.pair_id);
    BOOST_CHECK(found->terms.long_token_id == rec.terms.long_token_id);
    BOOST_CHECK(found->terms.short_token_id == rec.terms.short_token_id);
    BOOST_CHECK_EQUAL(found->terms.lot_count, rec.terms.lot_count);
    BOOST_CHECK(found->long_icu_outpoint == rec.long_icu_outpoint);
    BOOST_CHECK(found->short_icu_outpoint == rec.short_icu_outpoint);
    BOOST_CHECK(found->issue_txid == rec.issue_txid);
    BOOST_CHECK(found->lot_vaults == rec.lot_vaults);
    BOOST_CHECK(ComputeScalarNotePairId(found->terms) == rec.pair_id);
    BOOST_CHECK_EQUAL(reloaded.ListScalarNotePairs().size(), 1u);
}

BOOST_AUTO_TEST_CASE(record_validation_rejects_corruption)
{
    const ScalarNotePairRecord good = MakeRecord();
    std::string err;
    BOOST_CHECK(ValidateScalarNotePairRecord(good, /*expected_key=*/nullptr, err));
    BOOST_CHECK(ValidateScalarNotePairRecord(good, &good.pair_id, err)); // DB key matches derived id

    auto rej = [](ScalarNotePairRecord r) { std::string e; BOOST_CHECK(!ValidateScalarNotePairRecord(r, nullptr, e)); };

    { auto r = good; r.pair_id.begin()[0] ^= 0xFF; rej(r); }                           // id != H(terms)
    { uint256 wrong = good.pair_id; wrong.begin()[0] ^= 0xFF; std::string e;           // DB key != derived
      BOOST_CHECK(!ValidateScalarNotePairRecord(good, &wrong, e)); }
    { auto r = good; r.terms.lambda_q = 0; r.pair_id = ComputeScalarNotePairId(r.terms); rej(r); } // invalid terms
    { auto r = good; r.lot_vaults.pop_back(); rej(r); }                                // count != lot_count
    { auto r = good; r.lot_vaults.back() = r.lot_vaults.front(); rej(r); }             // duplicate vault
    { auto r = good; r.lot_vaults.back() = COutPoint(); rej(r); }                      // fully-null vault
    { auto r = good; r.lot_vaults.back() = COutPoint(Txid::FromUint256(uint256::ONE), COutPoint::NULL_INDEX); rej(r); } // NULL_INDEX vault
    { auto r = good; r.issue_txid.SetNull(); rej(r); }                                 // null issue_txid
    { auto r = good; r.register_long_txid.SetNull(); rej(r); }                         // unregistered L
    { auto r = good; r.register_short_txid.SetNull(); rej(r); }                        // unregistered S
    { auto r = good; r.long_icu_outpoint = COutPoint(Txid::FromUint256(Filled(0x55)), 0); rej(r); }  // ICU not from issue tx
    { auto r = good; r.short_icu_outpoint = r.long_icu_outpoint; rej(r); }             // identical ICUs
    { auto r = good; r.lot_vaults.back() = COutPoint(Txid::FromUint256(Filled(0x55)), 9); rej(r); }  // vault not from issue tx
}

BOOST_AUTO_TEST_CASE(register_rejects_invalid_record)
{
    ScalarNotePairRecord bad = MakeRecord();
    bad.lot_vaults.pop_back(); // count mismatch vs lot_count
    BOOST_CHECK_THROW(m_wallet.RegisterScalarNotePair(bad), std::runtime_error);
    BOOST_CHECK(!m_wallet.FindScalarNotePair(bad.pair_id).has_value());
    BOOST_CHECK(m_wallet.ListScalarNotePairs().empty());
}

BOOST_AUTO_TEST_SUITE_END()
