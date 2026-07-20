// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Slice 5f-2 — wallet persistence for bilateral scalar CFD contracts: a registered ScalarCfdContractRecord
// (the freshly-accepted state, vaults still null, FS-adaptor points set) survives a wallet reload
// (Register -> DuplicateMockDatabase -> LoadWallet -> Find/List), and RegisterScalarCfdContract's integrity
// gate rejects an id that does not derive from terms+salt or invalid terms. Mirrors
// scalar_note_pair_wallet_tests (DBKeys::SCALAR_CFD_CONTRACT{"scalarcfdcontract"}).

#include <wallet/scalar_cfd_contract.h>

#include <arith_uint256.h>
#include <assets/asset.h>             // SCALAR_FORMAT_RAW_U256_LE
#include <consensus/scalar_cfd_leaf.h>
#include <key.h>
#include <pubkey.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>

using namespace wallet;

namespace {

uint256 Filled(unsigned char b) { uint256 u; std::fill(u.begin(), u.end(), b); return u; }
CKey KeyFromSeed(uint8_t seed)
{
    uint256 s; std::fill(s.begin(), s.end(), seed);
    s.data()[0] = seed; s.data()[31] = 0x01;
    CKey k; k.Set(s.begin(), s.end(), /*fCompressed=*/true);
    BOOST_REQUIRE(k.IsValid());
    return k;
}
XOnlyPubKey XOnly(const CKey& k) { return XOnlyPubKey(k.GetPubKey()); }

ScalarCfdContractRecord MakeRecord()
{
    ScalarCfdContractRecord r;
    r.salt = Filled(0xBE);
    ScalarCfdContractTerms& t = r.terms;
    t.source_type = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
    t.payoff_mode = static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE);
    t.underlying_asset_id = Filled(0xA1);
    t.feed_id = 7;
    t.fixing_ref = 123456789ULL;
    t.publication_deadline_height = 150000;
    t.settle_lock_height = 150100;
    t.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    t.strike = ArithToUint256(arith_uint256(100));
    t.fallback_scalar = ArithToUint256(arith_uint256(95));
    t.collateral_asset_id = Filled(0xC0);
    t.long_leg.im = 10000;  t.long_leg.lambda_q = 1u << 16;
    t.long_leg.owner_key = XOnly(KeyFromSeed(0x11));  t.long_leg.cp_key = XOnly(KeyFromSeed(0x22));
    t.short_leg.im = 10000; t.short_leg.lambda_q = 1u << 16;
    t.short_leg.owner_key = XOnly(KeyFromSeed(0x22)); t.short_leg.cp_key = XOnly(KeyFromSeed(0x11));
    r.contract_id = ComputeScalarCfdContractId(t, r.salt);
    // Freshly-accepted state: NUMS vault internal keys + coop internals + FS adaptor points; vaults null.
    r.long_internal_key = XOnlyPubKey::NUMS_H;
    r.short_internal_key = XOnlyPubKey::NUMS_H;
    r.long_owner_internal = XOnly(KeyFromSeed(0x31)); r.long_cp_internal = XOnly(KeyFromSeed(0x32));
    r.short_owner_internal = XOnly(KeyFromSeed(0x32)); r.short_cp_internal = XOnly(KeyFromSeed(0x31));
    r.fs_tx_adaptor_point = XOnly(KeyFromSeed(0x41));
    r.counterparty_adaptor_point = XOnly(KeyFromSeed(0x42));
    r.fs_context = Filled(0x77);
    return r;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_contract_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(db_persistence_roundtrip)
{
    const ScalarCfdContractRecord rec = MakeRecord();
    m_wallet.RegisterScalarCfdContract(rec); // in-memory + WalletBatch write-through
    BOOST_REQUIRE(m_wallet.FindScalarCfdContract(rec.contract_id).has_value());

    std::unique_ptr<WalletDatabase> db = DuplicateMockDatabase(m_wallet.GetDatabase());
    CWallet reloaded(m_node.chain.get(), "", std::move(db));
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);

    const auto found = reloaded.FindScalarCfdContract(rec.contract_id);
    BOOST_REQUIRE(found.has_value());
    BOOST_CHECK(found->contract_id == rec.contract_id);
    BOOST_CHECK(found->salt == rec.salt);
    BOOST_CHECK(found->terms.long_leg.owner_key == rec.terms.long_leg.owner_key);
    BOOST_CHECK(found->terms.short_leg.cp_key == rec.terms.short_leg.cp_key);
    BOOST_CHECK(found->long_owner_internal == rec.long_owner_internal);
    BOOST_CHECK(found->short_cp_internal == rec.short_cp_internal);
    BOOST_CHECK(found->fs_tx_adaptor_point == rec.fs_tx_adaptor_point);
    BOOST_REQUIRE(found->counterparty_adaptor_point.has_value());
    BOOST_CHECK(*found->counterparty_adaptor_point == *rec.counterparty_adaptor_point);
    BOOST_CHECK(found->fs_context == rec.fs_context);
    // The deserialized terms must still hash to the same contract_id (no field drift).
    BOOST_CHECK(ComputeScalarCfdContractId(found->terms, found->salt) == rec.contract_id);
    BOOST_CHECK_EQUAL(reloaded.ListScalarCfdContracts().size(), 1u);
}

BOOST_AUTO_TEST_CASE(register_rejects_id_mismatch)
{
    ScalarCfdContractRecord bad = MakeRecord();
    bad.contract_id.begin()[0] ^= 0xFF; // no longer == ComputeScalarCfdContractId(terms, salt)
    BOOST_CHECK_THROW(m_wallet.RegisterScalarCfdContract(bad), std::runtime_error);
    BOOST_CHECK(m_wallet.ListScalarCfdContracts().empty());
}

BOOST_AUTO_TEST_CASE(register_rejects_invalid_terms)
{
    ScalarCfdContractRecord bad = MakeRecord();
    bad.terms.long_leg.lambda_q = 0;                                  // invalid terms
    bad.contract_id = ComputeScalarCfdContractId(bad.terms, bad.salt); // id matches, but Validate fails
    BOOST_CHECK_THROW(m_wallet.RegisterScalarCfdContract(bad), std::runtime_error);
    BOOST_CHECK(m_wallet.ListScalarCfdContracts().empty());
}

BOOST_AUTO_TEST_SUITE_END()
