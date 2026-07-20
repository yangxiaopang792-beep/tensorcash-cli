// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Slice B — wallet persistence for tokenized option series: the OptionSeriesRecord serializes
// round-trip, and a registered series survives a wallet reload (Write -> LoadWallet -> Find), exactly
// as DifficultyContractRecord does (DBKeys::OPTION_SERIES{"optseries"}).

#include <wallet/option_series.h>

#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
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
#include <vector>

using namespace wallet;

namespace {

XOnlyPubKey TestKey(unsigned char seed)
{
    std::vector<unsigned char> sk(32, 0);
    sk[31] = seed;
    CKey k;
    k.Set(sk.begin(), sk.end(), /*fCompressedIn=*/true);
    BOOST_REQUIRE(k.IsValid());
    return XOnlyPubKey(k.GetPubKey());
}

OptionSeriesRecord MakeOptionSeriesRecord()
{
    OptionSeriesTerms t;
    t.descriptor_version = kOptionDescriptorVersion;
    t.issuance_mode = OPTION_ISSUANCE_SELF;
    t.leaf_set = OPTION_LEAFSET_SETTLE_BUYBACK;
    t.writer_key = TestKey(0x11);
    t.strike_nbits = 0x1d00ffff;
    t.fixing_height = 150000;
    t.settle_lock_height = 150100;
    t.lambda_q = 218453;
    t.lot_im_sats = 3'000'000'000;
    t.lot_count = 4;
    t.reference_premium_sats = 50'000'000'000;
    std::fill(t.series_salt.begin(), t.series_salt.end(), 0x5a);

    OptionSeriesRecord rec;
    rec.terms = t;
    rec.series_id = ComputeOptionSeriesId(t);
    // icu_outpoint + every lot vault are outputs of the issuance tx, so they all reference issue_txid.
    rec.issue_txid = uint256::ONE;
    rec.icu_outpoint = COutPoint(Txid::FromUint256(uint256::ONE), 7);
    std::fill(rec.register_txid.begin(), rec.register_txid.end(), 0x33); // earlier registration tx (provenance)
    // Exactly lot_count (=4) funded lot vaults — the record integrity gate requires this.
    rec.lot_vaults = {COutPoint(Txid::FromUint256(uint256::ONE), 0),
                      COutPoint(Txid::FromUint256(uint256::ONE), 1),
                      COutPoint(Txid::FromUint256(uint256::ONE), 2),
                      COutPoint(Txid::FromUint256(uint256::ONE), 3)};
    return rec;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(option_series_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(record_serialization_roundtrip)
{
    const OptionSeriesRecord rec = MakeOptionSeriesRecord();

    DataStream ss{};
    ss << rec;
    OptionSeriesRecord back;
    ss >> back;

    BOOST_CHECK(back.series_id == rec.series_id);
    BOOST_CHECK(back.icu_outpoint == rec.icu_outpoint);
    BOOST_CHECK(back.register_txid == rec.register_txid);
    BOOST_CHECK(back.issue_txid == rec.issue_txid);
    BOOST_CHECK(back.lot_vaults == rec.lot_vaults);
    BOOST_CHECK_EQUAL(back.terms.descriptor_version, rec.terms.descriptor_version);
    BOOST_CHECK_EQUAL(back.terms.issuance_mode, rec.terms.issuance_mode);
    BOOST_CHECK_EQUAL(back.terms.leaf_set, rec.terms.leaf_set);
    BOOST_CHECK(back.terms.writer_key == rec.terms.writer_key);
    BOOST_CHECK_EQUAL(back.terms.lambda_q, rec.terms.lambda_q);
    BOOST_CHECK_EQUAL(back.terms.lot_im_sats, rec.terms.lot_im_sats);
    BOOST_CHECK_EQUAL(back.terms.lot_count, rec.terms.lot_count);
    BOOST_CHECK_EQUAL(back.terms.reference_premium_sats, rec.terms.reference_premium_sats);
    BOOST_CHECK(back.terms.series_salt == rec.terms.series_salt);
    // The deserialized terms must still hash to the same series_id (no field drift).
    BOOST_CHECK(ComputeOptionSeriesId(back.terms) == rec.series_id);
}

// `direction` is persisted ONLY for descriptor_version >= 2: a v1 record stays byte-identical to a
// pre-direction record (the field is not written), and an old blob deserializes with direction = CALL.
BOOST_AUTO_TEST_CASE(terms_persistence_direction_backcompat)
{
    OptionSeriesTerms v1 = MakeOptionSeriesRecord().terms;
    BOOST_REQUIRE_EQUAL(v1.descriptor_version, kOptionDescriptorVersion);
    v1.direction = OPTION_DIRECTION_PUT;  // in-memory junk that MUST NOT be written for a v1 record

    DataStream s1{};
    s1 << v1;
    const size_t v1_size = s1.size();
    OptionSeriesTerms v1_back;
    s1 >> v1_back;
    BOOST_CHECK_EQUAL(v1_back.direction, OPTION_DIRECTION_CALL);  // a v1 (pre-direction) blob reads as CALL

    OptionSeriesTerms v2 = v1;
    v2.descriptor_version = kOptionDescriptorVersionDirectional;
    v2.direction = OPTION_DIRECTION_PUT;
    DataStream s2{};
    s2 << v2;
    BOOST_CHECK_EQUAL(s2.size(), v1_size + 1);  // v2 carries exactly one extra byte: the direction
    OptionSeriesTerms v2_back;
    s2 >> v2_back;
    BOOST_CHECK_EQUAL(v2_back.direction, OPTION_DIRECTION_PUT);
}

BOOST_AUTO_TEST_CASE(db_persistence_roundtrip)
{
    const OptionSeriesRecord rec = MakeOptionSeriesRecord();
    m_wallet.RegisterOptionSeries(rec); // in-memory + WalletBatch write-through
    BOOST_REQUIRE(m_wallet.FindOptionSeries(rec.series_id).has_value());

    // Reload a fresh wallet from a duplicate of the on-disk database.
    std::unique_ptr<WalletDatabase> db = DuplicateMockDatabase(m_wallet.GetDatabase());
    CWallet reloaded(m_node.chain.get(), "", std::move(db));
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);

    const auto found = reloaded.FindOptionSeries(rec.series_id);
    BOOST_REQUIRE(found.has_value());
    BOOST_CHECK(found->series_id == rec.series_id);
    BOOST_CHECK(found->terms.writer_key == rec.terms.writer_key);
    BOOST_CHECK_EQUAL(found->terms.lot_count, rec.terms.lot_count);
    BOOST_CHECK_EQUAL(found->terms.lot_im_sats, rec.terms.lot_im_sats);
    BOOST_CHECK(found->icu_outpoint == rec.icu_outpoint);
    BOOST_CHECK(found->register_txid == rec.register_txid);
    BOOST_CHECK(found->issue_txid == rec.issue_txid);
    BOOST_CHECK(found->lot_vaults == rec.lot_vaults);
    BOOST_CHECK(ComputeOptionSeriesId(found->terms) == rec.series_id);

    BOOST_CHECK_EQUAL(reloaded.ListOptionSeries().size(), 1u);
}

// The integrity gate (ValidateOptionSeriesRecord) rejects every way a record can mismatch its terms.
BOOST_AUTO_TEST_CASE(record_validation_rejects_corruption)
{
    const OptionSeriesRecord good = MakeOptionSeriesRecord();
    std::string err;
    BOOST_CHECK(ValidateOptionSeriesRecord(good, /*expected_key=*/nullptr, err));
    BOOST_CHECK(ValidateOptionSeriesRecord(good, &good.series_id, err)); // DB key matches derived id

    // (a) series_id != ComputeOptionSeriesId(terms)
    { OptionSeriesRecord r = good; r.series_id.begin()[0] ^= 0xFF;
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (b) DB key != derived id (the load-path mismatch)
    { uint256 wrong = good.series_id; wrong.begin()[0] ^= 0xFF;
      BOOST_CHECK(!ValidateOptionSeriesRecord(good, &wrong, err)); }
    // (c) invalid terms (zero leverage) — re-hash so the id matches, isolating the terms failure
    { OptionSeriesRecord r = good; r.terms.lambda_q = 0; r.series_id = ComputeOptionSeriesId(r.terms);
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (d) lot_vaults count != lot_count
    { OptionSeriesRecord r = good; r.lot_vaults.pop_back();
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (e) duplicate lot vault outpoint
    { OptionSeriesRecord r = good; r.lot_vaults.back() = r.lot_vaults.front();
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (f) null lot vault outpoint
    { OptionSeriesRecord r = good; r.lot_vaults.back() = COutPoint();
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (g) null issue_txid
    { OptionSeriesRecord r = good; r.issue_txid.SetNull();
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (h) icu_outpoint references a tx other than issue_txid
    { OptionSeriesRecord r = good; uint256 other; std::fill(other.begin(), other.end(), 0x55);
      r.icu_outpoint = COutPoint(Txid::FromUint256(other), 7);
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
    // (i) a lot vault references a tx other than issue_txid
    { OptionSeriesRecord r = good; uint256 other; std::fill(other.begin(), other.end(), 0x55);
      r.lot_vaults.back() = COutPoint(Txid::FromUint256(other), 9);
      BOOST_CHECK(!ValidateOptionSeriesRecord(r, nullptr, err)); }
}

// RegisterOptionSeries refuses an invalid record and persists nothing (no half-written state).
BOOST_AUTO_TEST_CASE(register_rejects_invalid_record)
{
    OptionSeriesRecord bad = MakeOptionSeriesRecord();
    bad.lot_vaults.pop_back(); // count mismatch vs lot_count
    BOOST_CHECK_THROW(m_wallet.RegisterOptionSeries(bad), std::runtime_error);
    BOOST_CHECK(!m_wallet.FindOptionSeries(bad.series_id).has_value());
    BOOST_CHECK(m_wallet.ListOptionSeries().empty());
}

BOOST_AUTO_TEST_SUITE_END()
