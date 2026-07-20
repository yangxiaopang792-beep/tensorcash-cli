// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scalar_cfd_contract.h>

#include <arith_uint256.h>
#include <assets/asset.h>             // SCALAR_FORMAT_RAW_U256_LE
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT
#include <consensus/scalar_cfd.h>     // SCALARCFD_ASSET_OUTPUT_DUST
#include <consensus/scalar_cfd_leaf.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

using namespace wallet;

namespace {

//! Deterministic valid key from a seed byte.
CKey KeyFromSeed(uint8_t seed)
{
    uint256 s;
    std::fill(s.begin(), s.end(), seed);
    s.data()[0] = seed; s.data()[31] = 0x01; // keep it in range / non-zero
    CKey k;
    k.Set(s.begin(), s.end(), /*fCompressed=*/true);
    BOOST_REQUIRE(k.IsValid());
    return k;
}
XOnlyPubKey XOnly(const CKey& k) { return XOnlyPubKey(k.GetPubKey()); }

uint256 RawScalar(uint64_t v) { return ArithToUint256(arith_uint256(v)); }

// A self-consistent ISSUER_PUBLISHED, NATIVE-collateral CFD: K=100, both legs lambda=1x, im=10000.
ScalarCfdContractRecord ExampleRecord()
{
    ScalarCfdContractRecord r;
    r.salt = RawScalar(0xBEEF);
    ScalarCfdContractTerms& t = r.terms;
    t.source_type = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
    t.payoff_mode = static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE);
    t.underlying_asset_id = RawScalar(0xA1);
    t.feed_id = 7;
    t.fixing_ref = 1;
    t.publication_deadline_height = 1'000'000;
    t.settle_lock_height = 500;
    t.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    t.strike = RawScalar(100);
    t.fallback_scalar = RawScalar(95);
    t.collateral_asset_id = uint256{}; // native
    t.long_leg.im = 10000;  t.long_leg.lambda_q = 1u << 16;
    t.long_leg.owner_key = XOnly(KeyFromSeed(0x11));  // long party
    t.long_leg.cp_key    = XOnly(KeyFromSeed(0x22));  // short party
    t.short_leg.im = 10000; t.short_leg.lambda_q = 1u << 16;
    t.short_leg.owner_key = XOnly(KeyFromSeed(0x22)); // short party
    t.short_leg.cp_key    = XOnly(KeyFromSeed(0x11)); // long party
    r.contract_id = ComputeScalarCfdContractId(t, r.salt);
    // Open-time bindings (NUMS internal vaults + coop internal keys + outpoints).
    r.long_internal_key = XOnlyPubKey::NUMS_H;
    r.short_internal_key = XOnlyPubKey::NUMS_H;
    r.long_owner_internal = XOnly(KeyFromSeed(0x31));
    r.long_cp_internal    = XOnly(KeyFromSeed(0x32));
    r.short_owner_internal = XOnly(KeyFromSeed(0x32));
    r.short_cp_internal    = XOnly(KeyFromSeed(0x31));
    // Consistent opened state: both vaults reference the same open tx.
    r.open_txid = RawScalar(0xDD);
    r.long_vault = COutPoint(Txid::FromUint256(RawScalar(0xDD)), 0);
    r.short_vault = COutPoint(Txid::FromUint256(RawScalar(0xDD)), 1);
    return r;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_contract_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(contract_id_determinism)
{
    const ScalarCfdContractRecord r = ExampleRecord();
    BOOST_CHECK(ComputeScalarCfdContractId(r.terms, r.salt) == r.contract_id);
    // salt-sensitive
    BOOST_CHECK(ComputeScalarCfdContractId(r.terms, RawScalar(0xBEF0)) != r.contract_id);
    // terms-sensitive
    ScalarCfdContractTerms t2 = r.terms; t2.strike = RawScalar(101);
    BOOST_CHECK(ComputeScalarCfdContractId(t2, r.salt) != r.contract_id);
}

BOOST_AUTO_TEST_CASE(validate_accept_and_reject)
{
    std::string err;
    BOOST_CHECK(ExampleRecord().terms.Validate(err));

    auto rej = [](ScalarCfdContractTerms t) { std::string e; return !t.Validate(e); };
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.long_leg.lambda_q = 0; BOOST_CHECK(rej(t)); }
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.short_leg.im = MIN_SETTLE_OUTPUT - 1; BOOST_CHECK(rej(t)); }
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.long_leg.cp_key = t.long_leg.owner_key; BOOST_CHECK(rej(t)); }
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.settle_lock_height = 0; BOOST_CHECK(rej(t)); }
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.settle_lock_height = LOCKTIME_THRESHOLD; BOOST_CHECK(rej(t)); }
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.source_type = 9; BOOST_CHECK(rej(t)); }
    // ISSUER source with a zero underlying is inconsistent.
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.underlying_asset_id = uint256{}; BOOST_CHECK(rej(t)); }
    // CHAIN_INTRINSIC with a non-zero underlying is inconsistent.
    { ScalarCfdContractTerms t = ExampleRecord().terms;
      t.source_type = static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC);
      BOOST_CHECK(rej(t)); }
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.scalar_format_id = 0xFFFF; BOOST_CHECK(rej(t)); }
    // Non-canonical committed literals for a FIXED-WIDTH format are rejected here (the integrity gate), so a
    // persisted/derived record can't carry a strike/fallback the opcode would reject at settlement (Slice 6).
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.scalar_format_id = assets::SCALAR_FORMAT_U64_BE;
      t.strike = *uint256::FromHex(std::string(64, 'f')); BOOST_CHECK(rej(t)); }            // strike overflows u64
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.scalar_format_id = assets::SCALAR_FORMAT_U64_BE;
      t.strike = uint256{}; t.fallback_scalar = *uint256::FromHex(std::string(64, 'f')); BOOST_CHECK(rej(t)); } // fallback overflows u64
    // The SAME wide value is canonical under RAW_U256 (no width bound) -> accepted (check is format-specific).
    { ScalarCfdContractTerms t = ExampleRecord().terms; t.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_BE;
      t.strike = *uint256::FromHex(std::string(64, 'f')); t.fallback_scalar = t.strike;
      std::string e; BOOST_CHECK(t.Validate(e)); }
}

BOOST_AUTO_TEST_CASE(offer_commitment_binding)
{
    const ScalarCfdContractRecord r = ExampleRecord();
    const XOnlyPubKey po = r.terms.long_leg.owner_key, pc = r.terms.long_leg.cp_key;
    const uint256 base = ComputeScalarCfdOfferCommitment(0, r.terms, po, pc, r.salt);
    BOOST_CHECK(base == ComputeScalarCfdOfferCommitment(0, r.terms, po, pc, r.salt)); // deterministic
    BOOST_CHECK(base != ComputeScalarCfdOfferCommitment(1, r.terms, po, pc, r.salt)); // side
    BOOST_CHECK(base != ComputeScalarCfdOfferCommitment(0, r.terms, pc, po, r.salt)); // proposer keys
    BOOST_CHECK(base != ComputeScalarCfdOfferCommitment(0, r.terms, po, pc, RawScalar(7))); // salt
    ScalarCfdContractTerms t2 = r.terms; t2.fixing_ref = 2;
    BOOST_CHECK(base != ComputeScalarCfdOfferCommitment(0, t2, po, pc, r.salt)); // a fixing field
}

BOOST_AUTO_TEST_CASE(fs_adaptor_derivation)
{
    const CKey owner = KeyFromSeed(0x44);
    const uint256 salt = RawScalar(0x1234), ctx = RawScalar(0x5678);
    const auto [sec, pt] = DeriveScalarCfdFsAdaptor(owner, salt, ctx, SCALAR_CFD_FS_ROLE_PROPOSER);
    // deterministic
    const auto again = DeriveScalarCfdFsAdaptor(owner, salt, ctx, SCALAR_CFD_FS_ROLE_PROPOSER);
    BOOST_CHECK(again.first == sec && again.second == pt);
    // point == secret*G
    CKey k; k.Set(sec.begin(), sec.end(), true);
    BOOST_REQUIRE(k.IsValid());
    BOOST_CHECK(XOnlyPubKey(k.GetPubKey()) == pt);
    // role + context separation
    BOOST_CHECK(DeriveScalarCfdFsAdaptor(owner, salt, ctx, SCALAR_CFD_FS_ROLE_ACCEPTOR).first != sec);
    BOOST_CHECK(DeriveScalarCfdFsAdaptor(owner, salt, RawScalar(9), SCALAR_CFD_FS_ROLE_PROPOSER).first != sec);
}

BOOST_AUTO_TEST_CASE(leg_leaf_roundtrips_consensus_parser)
{
    const ScalarCfdContractRecord r = ExampleRecord();
    for (bool is_short : {false, true}) {
        const CScript leaf = BuildScalarCfdLegLeaf(r, is_short);
        ScalarCfdLeaf out;
        BOOST_REQUIRE(ParseScalarCfdLeaf(leaf, out));
        const ScalarCfdLegTerms& leg = is_short ? r.terms.short_leg : r.terms.long_leg;
        BOOST_CHECK(out.contract_id == r.contract_id);
        BOOST_CHECK_EQUAL(out.loss_direction, is_short ? 0x01 : 0x00);
        BOOST_CHECK_EQUAL(out.lambda_q, leg.lambda_q);
        BOOST_CHECK_EQUAL(out.vault_im, leg.im);
        BOOST_CHECK(out.owner_key == ToByteVector(leg.owner_key));
        BOOST_CHECK(out.cp_key == ToByteVector(leg.cp_key));
        BOOST_CHECK(out.strike == r.terms.strike);
        BOOST_CHECK_EQUAL(out.feed_id, r.terms.feed_id);
        BOOST_CHECK_EQUAL(out.settle_lock_height, static_cast<int64_t>(r.terms.settle_lock_height));
    }
}

BOOST_AUTO_TEST_CASE(coop_leaf_is_2of2_of_internal_keys)
{
    const ScalarCfdContractRecord r = ExampleRecord();
    const CScript coop = BuildScalarCfdCoopLeaf(r, /*is_short=*/false);
    CScript expect;
    expect << ToByteVector(r.long_owner_internal) << OP_CHECKSIGVERIFY
           << ToByteVector(r.long_cp_internal) << OP_CHECKSIG;
    BOOST_CHECK(coop == expect);
}

BOOST_AUTO_TEST_CASE(vault_output_keys_are_distinct_per_leg)
{
    const ScalarCfdContractRecord r = ExampleRecord();
    TaprootBuilder lb = CreateScalarCfdVaultBuilder(r, false, r.long_internal_key);
    TaprootBuilder sb = CreateScalarCfdVaultBuilder(r, true, r.short_internal_key);
    BOOST_REQUIRE(lb.IsComplete() && sb.IsComplete());
    // Same NUMS internal key, but the committed leaves differ -> distinct tweaked output keys.
    BOOST_CHECK(lb.GetOutput() != sb.GetOutput());
}

BOOST_AUTO_TEST_CASE(settlement_skeleton_payout_and_witness)
{
    const ScalarCfdContractRecord r = ExampleRecord();
    // Long leg, X=90 < K=100, lambda 1x: loss fraction 0.1 -> cp(short) 1000, owner(long) 9000.
    ScalarCfdSettlementSkeleton sk;
    std::string err;
    BOOST_REQUIRE_MESSAGE(BuildScalarCfdSettlementSkeleton(r, /*is_short=*/false, arith_uint256(90), sk, err), err);
    BOOST_CHECK_EQUAL(sk.payout.payout_owner, 9000u);
    BOOST_CHECK_EQUAL(sk.payout.payout_cp, 1000u);
    BOOST_CHECK_EQUAL(sk.payout.payout_owner + sk.payout.payout_cp, r.terms.long_leg.im);
    BOOST_CHECK_EQUAL(sk.nlocktime, r.terms.settle_lock_height);
    BOOST_CHECK(sk.vault_input.prevout == r.long_vault);
    BOOST_CHECK_EQUAL(sk.vault_input.scriptWitness.stack.size(), 2u); // [settle_leaf, control]
    // Native collateral -> payout outputs carry the value natively (no AssetTag) to P2TR(owner/cp).
    BOOST_REQUIRE_EQUAL(sk.payouts.size(), 2u);
    CScript owner_spk; owner_spk << OP_1 << ToByteVector(r.terms.long_leg.owner_key);
    BOOST_CHECK(sk.payouts[0].scriptPubKey == owner_spk);
    BOOST_CHECK_EQUAL(sk.payouts[0].nValue, 9000);
    BOOST_CHECK(sk.payouts[0].vExt.empty());

    // Unopened vault (null outpoint) -> rejected.
    ScalarCfdContractRecord r2 = r; r2.long_vault = COutPoint();
    ScalarCfdSettlementSkeleton sk2; std::string err2;
    BOOST_CHECK(!BuildScalarCfdSettlementSkeleton(r2, false, arith_uint256(90), sk2, err2));
}

BOOST_AUTO_TEST_CASE(settlement_skeleton_asset_collateral_uses_consensus_dust)
{
    // Asset-collateralised contract: the carrier nValue must be exactly the consensus dust the opcode
    // enforces (SCALARCFD_ASSET_OUTPUT_DUST), never caller-tunable; the payout rides in the AssetTag.
    ScalarCfdContractRecord r = ExampleRecord();
    r.terms.collateral_asset_id = RawScalar(0xC0);          // non-native collateral
    r.contract_id = ComputeScalarCfdContractId(r.terms, r.salt); // collateral is committed in contract_id
    ScalarCfdSettlementSkeleton sk;
    std::string err;
    BOOST_REQUIRE_MESSAGE(BuildScalarCfdSettlementSkeleton(r, /*is_short=*/false, arith_uint256(90), sk, err), err);
    BOOST_CHECK_EQUAL(sk.payout.payout_owner, 9000u);
    BOOST_CHECK_EQUAL(sk.payout.payout_cp, 1000u);
    BOOST_REQUIRE_EQUAL(sk.payouts.size(), 2u);
    for (const CTxOut& o : sk.payouts) {
        BOOST_CHECK_EQUAL(o.nValue, SCALARCFD_ASSET_OUTPUT_DUST); // consensus carrier dust
        BOOST_CHECK(!o.vExt.empty());                            // AssetTag(C, leg) present
    }
    CScript owner_spk; owner_spk << OP_1 << ToByteVector(r.terms.long_leg.owner_key);
    BOOST_CHECK(sk.payouts[0].scriptPubKey == owner_spk);
}

BOOST_AUTO_TEST_CASE(settlement_skeleton_dust_snaps_to_single_output)
{
    // Small IM: the losing leg snaps below the 546 dust floor, so its value goes wholly to the surviving
    // leg — the skeleton then emits EXACTLY ONE payout (never zero outputs).
    ScalarCfdContractRecord r = ExampleRecord();
    r.terms.long_leg.im = 600;
    r.terms.short_leg.im = 600;
    r.contract_id = ComputeScalarCfdContractId(r.terms, r.salt); // im is committed in contract_id
    ScalarCfdSettlementSkeleton sk;
    std::string err;
    // long leg, X=90<K=100, lambda 1x: cp = floor(0.1*600) = 60 < 546 -> cp snaps to 0, owner = 600.
    BOOST_REQUIRE_MESSAGE(BuildScalarCfdSettlementSkeleton(r, /*is_short=*/false, arith_uint256(90), sk, err), err);
    BOOST_CHECK_EQUAL(sk.payout.payout_owner, 600u);
    BOOST_CHECK_EQUAL(sk.payout.payout_cp, 0u);
    BOOST_REQUIRE_EQUAL(sk.payouts.size(), 1u); // exactly the surviving leg
    BOOST_CHECK_EQUAL(sk.payouts[0].nValue, 600);
    CScript owner_spk; owner_spk << OP_1 << ToByteVector(r.terms.long_leg.owner_key);
    BOOST_CHECK(sk.payouts[0].scriptPubKey == owner_spk);
}

BOOST_AUTO_TEST_CASE(record_validation_invariants)
{
    // A fully-accepted record (NUMS vault internals + valid coop internals + both FS adaptor points + ctx).
    ScalarCfdContractRecord r = ExampleRecord();
    r.fs_tx_adaptor_point = XOnly(KeyFromSeed(0x41));
    r.counterparty_adaptor_point = XOnly(KeyFromSeed(0x42));
    r.fs_context = RawScalar(0x77);
    std::string err;
    BOOST_CHECK_MESSAGE(ValidateScalarCfdContractRecord(r, nullptr, err), err);
    BOOST_CHECK(ValidateScalarCfdContractRecord(r, &r.contract_id, err)); // DB key matches

    auto rej = [](ScalarCfdContractRecord x) { std::string e; return !ValidateScalarCfdContractRecord(x, nullptr, e); };
    // contract_id / db-key (only terms+salt feed the id, so non-term mutations below need no recompute).
    { auto x = r; x.contract_id.begin()[0] ^= 0xFF; BOOST_CHECK(rej(x)); }
    { uint256 w = r.contract_id; w.begin()[0] ^= 0xFF; std::string e; BOOST_CHECK(!ValidateScalarCfdContractRecord(r, &w, e)); }
    // invalid terms (recompute id so the failure is Validate, not the id check).
    { auto x = r; x.terms.long_leg.lambda_q = 0; x.contract_id = ComputeScalarCfdContractId(x.terms, x.salt); BOOST_CHECK(rej(x)); }
    // non-NUMS vault internal (not part of contract_id).
    { auto x = r; x.long_internal_key = XOnly(KeyFromSeed(0x99)); BOOST_CHECK(rej(x)); }
    { auto x = r; x.short_internal_key = XOnly(KeyFromSeed(0x99)); BOOST_CHECK(rej(x)); }
    // invalid / missing coop internal.
    { auto x = r; x.long_owner_internal = XOnlyPubKey{}; BOOST_CHECK(rej(x)); }
    { auto x = r; x.short_cp_internal = XOnlyPubKey{}; BOOST_CHECK(rej(x)); }
    // incomplete Fair-Sign state.
    { auto x = r; x.fs_tx_adaptor_point = XOnlyPubKey{}; BOOST_CHECK(rej(x)); }
    { auto x = r; x.counterparty_adaptor_point.reset(); BOOST_CHECK(rej(x)); }
    { auto x = r; x.counterparty_adaptor_point = XOnlyPubKey{}; BOOST_CHECK(rej(x)); }
    { auto x = r; x.fs_context = uint256{}; BOOST_CHECK(rej(x)); }

    // Accepted state (no open_txid, no vaults) is also valid.
    { auto x = r; x.open_txid = uint256{}; x.long_vault = COutPoint{}; x.short_vault = COutPoint{}; std::string e;
      BOOST_CHECK(ValidateScalarCfdContractRecord(x, nullptr, e)); }
    // Opened-state inconsistencies (none change contract_id).
    { auto x = r; x.open_txid = uint256{}; BOOST_CHECK(rej(x)); }                              // vaults set, no open_txid
    { auto x = r; x.long_vault = COutPoint{}; BOOST_CHECK(rej(x)); }                           // open_txid set, vault null
    { auto x = r; x.short_vault = COutPoint(Txid::FromUint256(RawScalar(0x99)), 0); BOOST_CHECK(rej(x)); } // vault not from open tx
    { auto x = r; x.long_vault = COutPoint(Txid::FromUint256(RawScalar(0xDD)), COutPoint::NULL_INDEX); BOOST_CHECK(rej(x)); } // NULL_INDEX
    { auto x = r; x.short_vault = x.long_vault; BOOST_CHECK(rej(x)); } // long/short must be distinct outpoints
}

BOOST_AUTO_TEST_CASE(record_serialize_roundtrip_with_and_without_fs)
{
    // With FS adaptor fields populated.
    ScalarCfdContractRecord r = ExampleRecord();
    r.open_txid = RawScalar(0xCC);
    r.fs_tx_adaptor_point = XOnly(KeyFromSeed(0x55));
    r.counterparty_adaptor_point = XOnly(KeyFromSeed(0x66));
    r.fs_context = RawScalar(0x77);
    DataStream ss; ss << r;
    ScalarCfdContractRecord back; ss >> back;
    BOOST_CHECK(back.contract_id == r.contract_id);
    BOOST_CHECK(back.open_txid == r.open_txid);
    BOOST_CHECK(back.fs_tx_adaptor_point == r.fs_tx_adaptor_point);
    BOOST_REQUIRE(back.counterparty_adaptor_point.has_value());
    BOOST_CHECK(*back.counterparty_adaptor_point == *r.counterparty_adaptor_point);
    BOOST_CHECK(back.fs_context == r.fs_context);
    BOOST_CHECK(back.long_vault == r.long_vault && back.short_vault == r.short_vault);

    // Without FS (half-built record): null adaptor point -> no trailing fs bytes -> round-trips.
    ScalarCfdContractRecord r0 = ExampleRecord();
    DataStream ss0; ss0 << r0;
    ScalarCfdContractRecord back0; ss0 >> back0;
    BOOST_CHECK(back0.fs_tx_adaptor_point.IsNull());
    BOOST_CHECK(!back0.counterparty_adaptor_point.has_value());
    BOOST_CHECK(back0.contract_id == r0.contract_id);
}

BOOST_AUTO_TEST_SUITE_END()
