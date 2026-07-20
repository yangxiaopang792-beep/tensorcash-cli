// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scalar_note_pair.h>

#include <addresstype.h>             // WitnessV1Taproot, GetScriptForDestination
#include <arith_uint256.h>
#include <assets/asset.h>            // SCALAR_FORMAT_RAW_U256_LE, ParseIssuerReg, MINT_ALLOWED
#include <wallet/asset_registration.h> // BuildIssuerRegV1
#include <consensus/amount.h>        // MAX_MONEY
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT
#include <consensus/scalar_cfd.h>    // ComputeScalarCfdPayout, ScalarLossDenominator
#include <consensus/scalar_cfd_leaf.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace wallet;

namespace {

uint256 Bytes32(uint8_t b)
{
    uint256 u;
    std::fill(u.begin(), u.end(), b);
    return u;
}

// A self-consistent ISSUER_PUBLISHED, asset-collateralised note pair (capped spread, STRIKE mode).
ScalarNotePairTerms ExampleTerms()
{
    ScalarNotePairTerms t;
    t.descriptor_version = kScalarNotePairDescriptorVersion;
    t.source_type        = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
    t.payoff_mode        = static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE);
    t.loss_direction     = 0x00; // owner = long
    t.underlying_asset_id = Bytes32(0xA1);
    t.feed_id            = 7;
    t.fixing_ref         = 123456789ULL;
    t.publication_deadline_height = 150000;
    t.settle_lock_height = 150100;
    t.scalar_format_id   = assets::SCALAR_FORMAT_RAW_U256_LE;
    t.strike             = Bytes32(0x64);
    t.fallback_scalar    = Bytes32(0x5F);
    t.lambda_q           = 218453;
    t.collateral_asset_id = Bytes32(0xC0); // asset C
    t.vault_im           = 1'000'000;
    t.lot_count          = 100;
    t.series_salt        = Bytes32(0xEE);
    // §6.2: the token ids are the canonical derivation of the economics (set them last, after every
    // base field is populated). ValidateScalarNotePairTerms requires exactly these.
    std::tie(t.long_token_id, t.short_token_id) = DeriveScalarNotePairTokenIds(t);
    return t;
}

// Re-derive the canonical L/S after mutating any economic (base) field, so terms stay valid.
void RederiveTokens(ScalarNotePairTerms& t)
{
    std::tie(t.long_token_id, t.short_token_id) = DeriveScalarNotePairTokenIds(t);
}

// An AssetTag output: `amount` units of `asset_id` sent to `spk` (dust native carrier).
CTxOut AssetOut(const CScript& spk, const uint256& asset_id, uint64_t amount, CAmount nValue = 546)
{
    CTxOut o(nValue, spk);
    o.vExt = assets::BuildAssetTagTlv(asset_id, amount);
    return o;
}

// Execute a tapscript covenant leaf against a transaction's outputs. Returns true iff EvalScript
// succeeds AND the clean-stack result is a single truthy element (what VerifyWitnessProgram enforces).
bool RunCovenantLeaf(const CScript& leaf, const CTransaction& tx)
{
    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    ScriptError serr = SCRIPT_ERR_OK;
    const bool ok = EvalScript(stack, leaf, SCRIPT_VERIFY_TAPROOT, checker, SigVersion::TAPSCRIPT, execdata, &serr);
    return ok && stack.size() == 1 && stack.back() == std::vector<unsigned char>{0x01};
}

CTransaction TxWithOutputs(std::vector<CTxOut> vout)
{
    CMutableTransaction m;
    m.vin.emplace_back();
    m.vout = std::move(vout);
    return CTransaction(m);
}

CScript P2TRFill(unsigned char fill) { return CScript() << OP_1 << std::vector<unsigned char>(32, fill); }

// A child-ICU IssuerReg vExt for `asset_id` with cap `N`, MINT_ALLOWED, decimals 0, quorum 0 — exactly
// what BuildScalarNotePairIssuance's VerifyIssuerIcu requires.
std::vector<unsigned char> MakeIcuReg(const uint256& asset_id, uint32_t cap, const std::string& ticker,
                                      uint32_t policy_bits = assets::MINT_ALLOWED, uint16_t quorum = 0,
                                      uint8_t decimals = 0, uint16_t allowed_spk = assets::SPK_DEFAULT_ALLOWED,
                                      uint32_t kyc_flags = 0, uint32_t tfr_flags = 0, uint32_t icu_flags = 0)
{
    return wallet::BuildIssuerRegV1(
        asset_id, policy_bits, allowed_spk, ticker, decimals, /*unlock_fees=*/0, kyc_flags,
        /*vk_commitment=*/uint256{}, /*max_root_age=*/0, tfr_flags, /*compliance_root_commit=*/uint256{},
        icu_flags, /*issuance_cap_units=*/cap, /*icu_ctxt_commit=*/uint256{}, /*icu_plain_commit=*/uint256{},
        /*kdf_salt=*/std::array<unsigned char, 16>{}, /*icu_version=*/0, /*icu_visibility=*/0,
        /*core_policy_commit=*/uint256{}, /*policy_epoch=*/0, /*policy_quorum_bps=*/quorum);
}

ScalarFundedInput IcuInput(uint8_t txhash, uint32_t vout, const uint256& asset_id, uint32_t cap,
                           const std::string& ticker, CAmount bond = 10000)
{
    ScalarFundedInput in;
    in.outpoint = COutPoint(Txid::FromUint256(Bytes32(txhash)), vout);
    in.txout = CTxOut(bond, P2TRFill(0x01));
    in.txout.vExt = MakeIcuReg(asset_id, cap, ticker);
    return in;
}

ScalarCfdLeaf ExampleLeaf()
{
    ScalarCfdLeaf l;
    l.contract_id        = Bytes32(0x01);
    l.template_version   = SCALAR_CFD_TEMPLATE_VERSION_V1;
    l.settle_lock_height = 150100;
    l.source_type        = static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED);
    l.underlying_asset_id = Bytes32(0xA1);
    l.feed_id            = 7;
    l.fixing_ref         = 123456789ULL;
    l.publication_deadline_height = 150000;
    l.payoff_mode        = static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE);
    l.scalar_format_id   = assets::SCALAR_FORMAT_RAW_U256_LE;
    l.strike             = Bytes32(0x64);
    l.fallback_scalar    = Bytes32(0x5F);
    l.lambda_q           = 218453;
    l.loss_direction     = 0x00;
    l.collateral_asset_id = Bytes32(0xC0);
    l.vault_im           = 1'000'000;
    l.owner_key          = std::vector<unsigned char>(32, 0x77);
    l.cp_key             = std::vector<unsigned char>(32, 0x88);
    return l;
}

// Field-by-field equality of two parsed/constructed leaves.
void CheckLeafEqual(const ScalarCfdLeaf& a, const ScalarCfdLeaf& b)
{
    BOOST_CHECK(a.contract_id == b.contract_id);
    BOOST_CHECK_EQUAL(a.template_version, b.template_version);
    BOOST_CHECK_EQUAL(a.settle_lock_height, b.settle_lock_height);
    BOOST_CHECK_EQUAL(a.source_type, b.source_type);
    BOOST_CHECK(a.underlying_asset_id == b.underlying_asset_id);
    BOOST_CHECK_EQUAL(a.feed_id, b.feed_id);
    BOOST_CHECK_EQUAL(a.fixing_ref, b.fixing_ref);
    BOOST_CHECK_EQUAL(a.publication_deadline_height, b.publication_deadline_height);
    BOOST_CHECK_EQUAL(a.payoff_mode, b.payoff_mode);
    BOOST_CHECK_EQUAL(a.scalar_format_id, b.scalar_format_id);
    BOOST_CHECK(a.strike == b.strike);
    BOOST_CHECK(a.fallback_scalar == b.fallback_scalar);
    BOOST_CHECK_EQUAL(a.lambda_q, b.lambda_q);
    BOOST_CHECK_EQUAL(a.loss_direction, b.loss_direction);
    BOOST_CHECK(a.collateral_asset_id == b.collateral_asset_id);
    BOOST_CHECK_EQUAL(a.vault_im, b.vault_im);
    BOOST_CHECK(a.owner_key == b.owner_key);
    BOOST_CHECK(a.cp_key == b.cp_key);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(scalar_note_pair_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_roundtrip)
{
    const ScalarNotePairTerms t = ExampleTerms();
    const std::vector<unsigned char> d = SerializeScalarNotePairDescriptor(t);
    BOOST_CHECK_EQUAL(d.size(), 266u);

    const auto parsed = ParseScalarNotePairDescriptor(d);
    BOOST_REQUIRE(parsed.has_value());
    const ScalarNotePairTerms& p = *parsed;
    BOOST_CHECK_EQUAL(p.descriptor_version, t.descriptor_version);
    BOOST_CHECK_EQUAL(p.source_type, t.source_type);
    BOOST_CHECK_EQUAL(p.payoff_mode, t.payoff_mode);
    BOOST_CHECK_EQUAL(p.loss_direction, t.loss_direction);
    BOOST_CHECK(p.underlying_asset_id == t.underlying_asset_id);
    BOOST_CHECK_EQUAL(p.feed_id, t.feed_id);
    BOOST_CHECK_EQUAL(p.fixing_ref, t.fixing_ref);
    BOOST_CHECK_EQUAL(p.publication_deadline_height, t.publication_deadline_height);
    BOOST_CHECK_EQUAL(p.settle_lock_height, t.settle_lock_height);
    BOOST_CHECK_EQUAL(p.scalar_format_id, t.scalar_format_id);
    BOOST_CHECK(p.strike == t.strike);
    BOOST_CHECK(p.fallback_scalar == t.fallback_scalar);
    BOOST_CHECK_EQUAL(p.lambda_q, t.lambda_q);
    BOOST_CHECK(p.collateral_asset_id == t.collateral_asset_id);
    BOOST_CHECK_EQUAL(p.vault_im, t.vault_im);
    BOOST_CHECK(p.long_token_id == t.long_token_id);
    BOOST_CHECK(p.short_token_id == t.short_token_id);
    BOOST_CHECK_EQUAL(p.lot_count, t.lot_count);
    BOOST_CHECK(p.series_salt == t.series_salt);

    // Wrong length and a bad enum byte fail closed.
    std::vector<unsigned char> short_d = d; short_d.pop_back();
    BOOST_CHECK(!ParseScalarNotePairDescriptor(short_d).has_value());
    std::vector<unsigned char> bad_src = d; bad_src[1] = 0x05; // source_type out of range
    BOOST_CHECK(!ParseScalarNotePairDescriptor(bad_src).has_value());
}

BOOST_AUTO_TEST_CASE(id_determinism)
{
    const ScalarNotePairTerms t = ExampleTerms();
    BOOST_CHECK(ComputeScalarNotePairId(t) == ComputeScalarNotePairId(t));

    ScalarNotePairTerms t2 = t;
    t2.strike = Bytes32(0x65); // any field change → different id
    BOOST_CHECK(ComputeScalarNotePairId(t) != ComputeScalarNotePairId(t2));

    ScalarNotePairTerms t3 = t;
    t3.lot_count += 1;
    BOOST_CHECK(ComputeScalarNotePairId(t) != ComputeScalarNotePairId(t3));
}

BOOST_AUTO_TEST_CASE(leaf_builder_roundtrip)
{
    // Asset collateral, long owner, STRIKE mode.
    {
        const ScalarCfdLeaf l = ExampleLeaf();
        ScalarCfdLeaf out;
        BOOST_REQUIRE(ParseScalarCfdLeaf(BuildScalarCfdLeaf(l), out));
        CheckLeafEqual(l, out);
    }
    // Native collateral (zero sentinel), short owner, REALIZED mode.
    {
        ScalarCfdLeaf l = ExampleLeaf();
        l.collateral_asset_id = uint256{}; // NATIVE_SENTINEL
        l.loss_direction = 0x01;
        l.payoff_mode = static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED);
        l.settle_lock_height = 1; // smallest legal CLTV push
        ScalarCfdLeaf out;
        BOOST_REQUIRE(ParseScalarCfdLeaf(BuildScalarCfdLeaf(l), out));
        CheckLeafEqual(l, out);
    }
    // CHAIN_INTRINSIC: underlying pinned to zero (parser-enforced).
    {
        ScalarCfdLeaf l = ExampleLeaf();
        l.source_type = static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC);
        l.underlying_asset_id = uint256{};
        ScalarCfdLeaf out;
        BOOST_REQUIRE(ParseScalarCfdLeaf(BuildScalarCfdLeaf(l), out));
        CheckLeafEqual(l, out);
    }
}

BOOST_AUTO_TEST_CASE(derive_lot_deterministic_and_distinct)
{
    const ScalarNotePairTerms t = ExampleTerms();
    const uint256 pair_id = ComputeScalarNotePairId(t);

    const ScalarNoteLot a0 = DeriveScalarNoteLot(t, pair_id, 0);
    const ScalarNoteLot a0b = DeriveScalarNoteLot(t, pair_id, 0);
    // Determinism.
    BOOST_CHECK(a0.salt == a0b.salt);
    BOOST_CHECK(a0.contract_id == a0b.contract_id);
    BOOST_CHECK(a0.long_pot_spk == a0b.long_pot_spk);
    BOOST_CHECK(a0.short_pot_spk == a0b.short_pot_spk);
    BOOST_CHECK(a0.settle_leaf == a0b.settle_leaf);

    const ScalarNoteLot a1 = DeriveScalarNoteLot(t, pair_id, 1);
    // Distinct per index.
    BOOST_CHECK(a0.salt != a1.salt);
    BOOST_CHECK(a0.contract_id != a1.contract_id);
    BOOST_CHECK(a0.long_sink_spk != a1.long_sink_spk);
    BOOST_CHECK(a0.short_sink_spk != a1.short_sink_spk);
    BOOST_CHECK(a0.long_pot_spk != a1.long_pot_spk);
    BOOST_CHECK(a0.short_pot_spk != a1.short_pot_spk);
    BOOST_CHECK(a0.settle_leaf != a1.settle_leaf);

    // The two sides of one lot are distinct families (long sink != short sink, long pot != short pot).
    BOOST_CHECK(a0.long_sink_spk != a0.short_sink_spk);
    BOOST_CHECK(a0.long_pot_spk != a0.short_pot_spk);
}

BOOST_AUTO_TEST_CASE(lot_topology_owner_long_cp_short)
{
    const ScalarNotePairTerms t = ExampleTerms();
    const uint256 pair_id = ComputeScalarNotePairId(t);
    const ScalarNoteLot lot = DeriveScalarNoteLot(t, pair_id, 3);

    // The settle leaf must parse and bind owner_key = long pot key, cp_key = short pot key (§6.1).
    ScalarCfdLeaf parsed;
    BOOST_REQUIRE(ParseScalarCfdLeaf(lot.settle_leaf, parsed));
    BOOST_CHECK(parsed.owner_key == ToByteVector(lot.long_pot_key));
    BOOST_CHECK(parsed.cp_key == ToByteVector(lot.short_pot_key));

    // The settle leaf carries the descriptor's shared economics + this lot's contract_id.
    BOOST_CHECK(parsed.contract_id == lot.contract_id);
    BOOST_CHECK(parsed.underlying_asset_id == t.underlying_asset_id);
    BOOST_CHECK_EQUAL(parsed.feed_id, t.feed_id);
    BOOST_CHECK_EQUAL(parsed.fixing_ref, t.fixing_ref);
    BOOST_CHECK_EQUAL(parsed.payoff_mode, t.payoff_mode);
    BOOST_CHECK(parsed.collateral_asset_id == t.collateral_asset_id);
    BOOST_CHECK_EQUAL(parsed.vault_im, t.vault_im);
    BOOST_CHECK_EQUAL(parsed.loss_direction, t.loss_direction);

    // The long pot binds token L; the short pot binds token S.
    BOOST_CHECK(lot.long_pot_leaf == BuildScalarPotLeaf(t.long_token_id, lot.long_sink_spk));
    BOOST_CHECK(lot.short_pot_leaf == BuildScalarPotLeaf(t.short_token_id, lot.short_sink_spk));

    // Vault taptree {settle, unwind} is assembled.
    BOOST_CHECK(!lot.unwind_leaf.empty());
    BOOST_CHECK_EQUAL(lot.vault_spk.size(), 34u); // P2TR: OP_1 <0x20> <32-byte output key>
}

BOOST_AUTO_TEST_CASE(validate_terms)
{
    std::string err;
    BOOST_CHECK(ValidateScalarNotePairTerms(ExampleTerms(), err));

    // reject_economic mutates a BASE field then RE-DERIVES the canonical L/S, so the canonical-id check
    // passes and the specific rule under test is what fails (otherwise every base mutation would just
    // trip the token-id check and mask the rule).
    auto reject_economic = [](auto mutate) {
        ScalarNotePairTerms t = ExampleTerms();
        mutate(t);
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(!ValidateScalarNotePairTerms(t, e));
        BOOST_CHECK(!e.empty());
    };
    // reject_token mutates the token ids directly (no re-derive): exercises the L/S-specific rules and
    // the canonical-mismatch rule.
    auto reject_token = [](auto mutate) {
        ScalarNotePairTerms t = ExampleTerms();
        mutate(t);
        std::string e;
        BOOST_CHECK(!ValidateScalarNotePairTerms(t, e));
        BOOST_CHECK(!e.empty());
    };

    reject_economic([](ScalarNotePairTerms& t){ t.descriptor_version = 9; });
    reject_economic([](ScalarNotePairTerms& t){ t.source_type = 5; });
    reject_economic([](ScalarNotePairTerms& t){ t.payoff_mode = 5; });
    reject_economic([](ScalarNotePairTerms& t){ t.loss_direction = 5; });
    reject_economic([](ScalarNotePairTerms& t){ t.scalar_format_id = 0xFFFF; });
    // Non-canonical committed literals for a fixed-width format are rejected at the integrity gate (Slice 6).
    reject_economic([](ScalarNotePairTerms& t){ t.scalar_format_id = assets::SCALAR_FORMAT_U64_BE; t.strike = *uint256::FromHex(std::string(64, 'f')); });
    reject_economic([](ScalarNotePairTerms& t){ t.scalar_format_id = assets::SCALAR_FORMAT_U64_BE; t.strike = uint256{}; t.fallback_scalar = *uint256::FromHex(std::string(64, 'f')); });
    reject_economic([](ScalarNotePairTerms& t){ t.lot_count = 0; });
    reject_economic([](ScalarNotePairTerms& t){ t.lambda_q = 0; });
    reject_economic([](ScalarNotePairTerms& t){ t.vault_im = static_cast<uint64_t>(MIN_SETTLE_OUTPUT) - 1; });
    reject_economic([](ScalarNotePairTerms& t){ t.settle_lock_height = 0; });
    reject_economic([](ScalarNotePairTerms& t){ t.settle_lock_height = LOCKTIME_THRESHOLD; });
    reject_economic([](ScalarNotePairTerms& t){ t.underlying_asset_id = uint256{}; }); // ISSUER needs U
    reject_economic([](ScalarNotePairTerms& t){ // CHAIN must have zero U
        t.source_type = static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC);
        t.underlying_asset_id = Bytes32(0xA1);
    });

    reject_token([](ScalarNotePairTerms& t){ t.long_token_id = uint256{}; });
    reject_token([](ScalarNotePairTerms& t){ t.short_token_id = t.long_token_id; });
    reject_token([](ScalarNotePairTerms& t){ t.collateral_asset_id = t.long_token_id; }); // L == C
    reject_token([](ScalarNotePairTerms& t){ t.long_token_id = Bytes32(0xAB); });   // non-canonical L
    reject_token([](ScalarNotePairTerms& t){ // swap L/S → non-canonical (order matters)
        std::swap(t.long_token_id, t.short_token_id);
    });

    // CHAIN_INTRINSIC with zero U is accepted (structurally) once tokens are re-derived for the new base.
    {
        ScalarNotePairTerms t = ExampleTerms();
        t.source_type = static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC);
        t.underlying_asset_id = uint256{};
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(ValidateScalarNotePairTerms(t, e));
    }

    // Native collateral (zero C) is accepted; L/S differ from the zero C because they are non-null.
    {
        ScalarNotePairTerms t = ExampleTerms();
        t.collateral_asset_id = uint256{};
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(ValidateScalarNotePairTerms(t, e));
    }

    // A wide strike/fallback that overflows U64 IS canonical under RAW_U256 (no width bound) -> accepted.
    // Mirrors the bilateral RAW-wide acceptance, proving the canonicality gate is format-specific.
    {
        ScalarNotePairTerms t = ExampleTerms();
        t.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_BE;
        t.strike = *uint256::FromHex(std::string(64, 'f'));
        t.fallback_scalar = t.strike;
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(ValidateScalarNotePairTerms(t, e));
    }
}

BOOST_AUTO_TEST_CASE(validate_native_large_value)
{
    // Native total collateral above MAX_MONEY is rejected without any implementation-defined
    // uint64->CAmount cast (the check compares in uint64 before casting).
    const uint64_t kMaxMoneyU = static_cast<uint64_t>(MAX_MONEY);

    // total = lot_count * vault_im just over MAX_MONEY. (Re-derive tokens so the native rule is what
    // fails, not the canonical-id check.)
    {
        ScalarNotePairTerms t = ExampleTerms();
        t.collateral_asset_id = uint256{}; // native
        t.lot_count = 2;
        t.vault_im = kMaxMoneyU; // total = 2*MAX_MONEY > MAX_MONEY
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(!ValidateScalarNotePairTerms(t, e));
    }
    // A single vault_im above INT64_MAX (would be UB if cast to CAmount before the range check).
    {
        ScalarNotePairTerms t = ExampleTerms();
        t.collateral_asset_id = uint256{};
        t.lot_count = 1;
        t.vault_im = (static_cast<uint64_t>(1) << 63) + 7; // > INT64_MAX, > MAX_MONEY
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(!ValidateScalarNotePairTerms(t, e));
    }
    // The same oversized vault_im with an ASSET collateral is NOT a native-MoneyRange failure (asset
    // units are uint64), so it passes the native check (the uint64 overflow guard still applies for N>1).
    {
        ScalarNotePairTerms t = ExampleTerms();
        t.lot_count = 1;
        t.vault_im = (static_cast<uint64_t>(1) << 63) + 7;
        RederiveTokens(t);
        std::string e;
        BOOST_CHECK(ValidateScalarNotePairTerms(t, e));
    }
}

BOOST_AUTO_TEST_CASE(lot_topology_loss_direction_short)
{
    // loss_direction == 1 (owner is the SHORT leg). Token L must still track the LONG leg: with the
    // pots assigned by direction, owner_key = short pot (S) and cp_key = long pot (L).
    ScalarNotePairTerms t = ExampleTerms();
    t.loss_direction = 0x01;
    t.strike = ArithToUint256(arith_uint256(100)); // clean K for the payout sanity below
    RederiveTokens(t); // loss_direction/strike are base fields → re-derive canonical L/S
    std::string err;
    BOOST_REQUIRE(ValidateScalarNotePairTerms(t, err));

    const uint256 pair_id = ComputeScalarNotePairId(t);
    const ScalarNoteLot lot = DeriveScalarNoteLot(t, pair_id, 0);

    ScalarCfdLeaf parsed;
    BOOST_REQUIRE(ParseScalarCfdLeaf(lot.settle_leaf, parsed));
    BOOST_CHECK(parsed.owner_key == ToByteVector(lot.short_pot_key)); // owner = short leg
    BOOST_CHECK(parsed.cp_key == ToByteVector(lot.long_pot_key));     // cp = long leg
    BOOST_CHECK_EQUAL(parsed.loss_direction, 0x01);

    // The opcode computes short_leg = (loss_dir == 1), pays payout_owner -> owner_key (short pot S),
    // payout_cp -> cp_key (long pot L). So the LONG token's pot (cp_key) gains as X rises above K and
    // gets nothing when X falls below K — i.e. genuine long exposure.
    const arith_uint256 K = UintToArith256(t.strike);
    const uint64_t dust = static_cast<uint64_t>(MIN_SETTLE_OUTPUT);
    ScalarCfdPayout up{}, dn{};
    // X = 110 > K: short owner loses, long (cp) gains.
    BOOST_REQUIRE(ComputeScalarCfdPayout(K, arith_uint256(110), ScalarLossDenominator::STRIKE,
                                         t.lambda_q, t.vault_im, /*short_leg=*/true, dust, up));
    // X = 90 < K: short owner keeps full, long (cp) gets nothing.
    BOOST_REQUIRE(ComputeScalarCfdPayout(K, arith_uint256(90), ScalarLossDenominator::STRIKE,
                                         t.lambda_q, t.vault_im, /*short_leg=*/true, dust, dn));
    BOOST_CHECK_GT(up.payout_cp, 0u);          // long pot (cp_key) gains on the upside
    BOOST_CHECK_EQUAL(dn.payout_cp, 0u);       // long pot (cp_key) flat on the downside
    BOOST_CHECK_EQUAL(up.payout_owner + up.payout_cp, t.vault_im); // L/S split sums to collateral
}

BOOST_AUTO_TEST_CASE(vault_taptree_and_unwind_leaf)
{
    const ScalarNotePairTerms t = ExampleTerms();
    const uint256 pair_id = ComputeScalarNotePairId(t);
    const ScalarNoteLot lot = DeriveScalarNoteLot(t, pair_id, 0);

    // The unwind leaf requires BOTH tokens to their sinks: == BuildScalarUnwindLeaf(L, S, sinks).
    BOOST_CHECK(lot.unwind_leaf == BuildScalarUnwindLeaf(t.long_token_id, lot.long_sink_spk,
                                                         t.short_token_id, lot.short_sink_spk));

    // Opcode structure: two OP_OUTPUTMATCH_ASSET with a single OP_VERIFY strictly between them, and the
    // second match terminal (so exactly one clean-stack element remains).
    std::vector<opcodetype> ops;
    {
        CScript::const_iterator pc = lot.unwind_leaf.begin();
        opcodetype op; std::vector<unsigned char> data;
        while (pc != lot.unwind_leaf.end()) { BOOST_REQUIRE(lot.unwind_leaf.GetOp(pc, op, data)); ops.push_back(op); }
    }
    std::vector<size_t> match_pos, verify_pos;
    for (size_t i = 0; i < ops.size(); ++i) {
        if (ops[i] == OP_OUTPUTMATCH_ASSET) match_pos.push_back(i);
        if (ops[i] == OP_VERIFY) verify_pos.push_back(i);
    }
    BOOST_REQUIRE_EQUAL(match_pos.size(), 2u);
    BOOST_REQUIRE_EQUAL(verify_pos.size(), 1u);
    BOOST_CHECK(match_pos[0] < verify_pos[0] && verify_pos[0] < match_pos[1]);
    BOOST_CHECK_EQUAL(match_pos[1], ops.size() - 1); // terminal

    // Vault determinism + the {settle, unwind} taptree reproduces vault_spk.
    BOOST_CHECK(DeriveScalarNoteLot(t, pair_id, 0).vault_spk == lot.vault_spk);
    TaprootBuilder b = CreateScalarVaultBuilder(lot.settle_leaf, lot.unwind_leaf);
    BOOST_REQUIRE(b.IsComplete());
    BOOST_CHECK(lot.vault_spk == GetScriptForDestination(WitnessV1Taproot{b.GetOutput()}));

    // Distinct per index.
    const ScalarNoteLot lot1 = DeriveScalarNoteLot(t, pair_id, 1);
    BOOST_CHECK(lot1.vault_spk != lot.vault_spk);
    BOOST_CHECK(lot1.unwind_leaf != lot.unwind_leaf);
}

BOOST_AUTO_TEST_CASE(unwind_leaf_execution)
{
    // The unwind leaf must EXECUTE (not just have the right opcodes): 1 L → long sink AND 1 S → short
    // sink passes; any missing/wrong/over-counted leg fails. OP_OUTPUTMATCH_ASSET pushes a bool, so the
    // OP_VERIFY collapses the first result and the second is the clean-stack terminal.
    const uint256 L = Bytes32(0x11), S = Bytes32(0x22);
    const CScript lsink = CScript() << OP_1 << std::vector<unsigned char>(32, 0xA0);
    const CScript ssink = CScript() << OP_1 << std::vector<unsigned char>(32, 0xB0);
    const CScript leaf = BuildScalarUnwindLeaf(L, lsink, S, ssink);

    // Valid complete set.
    BOOST_CHECK(RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(lsink, L, 1), AssetOut(ssink, S, 1)})));
    // Extra unrelated outputs do not break it (the matcher is existential).
    BOOST_CHECK(RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(lsink, L, 1), AssetOut(ssink, S, 1),
                                                     CTxOut(CAmount{1000}, ssink)})));

    // Missing S → first match VERIFYs, second is false → clean-stack false.
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(lsink, L, 1)})));
    // Missing L → first match false → OP_VERIFY aborts.
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(ssink, S, 1)})));
    // Wrong sink for L (L sent to the short sink).
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(ssink, L, 1), AssetOut(ssink, S, 1)})));
    // Wrong token id on the short leg (carries L's id).
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(lsink, L, 1), AssetOut(ssink, L, 1)})));
    // Over-counted legs (2 units, not exactly 1).
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(lsink, L, 2), AssetOut(ssink, S, 1)})));
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(lsink, L, 1), AssetOut(ssink, S, 2)})));
}

BOOST_AUTO_TEST_CASE(token_id_derivation)
{
    const ScalarNotePairTerms t = ExampleTerms();
    const auto ids = DeriveScalarNotePairTokenIds(t);

    // ExampleTerms stores the canonical ids; L != S.
    BOOST_CHECK(t.long_token_id == ids.first);
    BOOST_CHECK(t.short_token_id == ids.second);
    BOOST_CHECK(ids.first != ids.second);

    // The derivation IGNORES the stored token ids (non-circular: it hashes only the base economics).
    ScalarNotePairTerms t2 = t;
    t2.long_token_id = Bytes32(0xAB);
    t2.short_token_id = Bytes32(0xCD);
    BOOST_CHECK(DeriveScalarNotePairTokenIds(t2) == ids);

    // Any economic (base) field change moves both ids.
    ScalarNotePairTerms t3 = t; t3.lambda_q += 1;
    BOOST_CHECK(DeriveScalarNotePairTokenIds(t3) != ids);
    ScalarNotePairTerms t4 = t; t4.series_salt = Bytes32(0x01);
    BOOST_CHECK(DeriveScalarNotePairTokenIds(t4) != ids);

    // The base descriptor is exactly the full descriptor minus the two 32-byte token ids.
    BOOST_CHECK_EQUAL(SerializeScalarNotePairBaseDescriptor(t).size(), 266u - 64u);
}

BOOST_AUTO_TEST_CASE(icu_metadata_carries_descriptor)
{
    const ScalarNotePairTerms t = ExampleTerms();
    const std::vector<unsigned char> meta = BuildScalarNotePairIcuMetadata(t);
    BOOST_CHECK(!meta.empty());
    // The machine band embeds the EXACT descriptor hex so a verifier can recompute pair_id.
    const std::string s(meta.begin(), meta.end());
    BOOST_CHECK(s.find(HexStr(SerializeScalarNotePairDescriptor(t))) != std::string::npos);
    BOOST_CHECK(s.find("TSC-ICU-SCALARNOTEPAIR-1") != std::string::npos);

    // fixing_ref and (asset) vault_im are valid uint64_t and may exceed INT64_MAX — they must be
    // encoded losslessly (no implementation-defined uint64->int64 cast). Use asset collateral so the
    // oversized vault_im is legal.
    ScalarNotePairTerms big = ExampleTerms();
    big.fixing_ref = (static_cast<uint64_t>(1) << 63) + 5; // 9223372036854775813
    big.vault_im   = (static_cast<uint64_t>(1) << 63) + 9; // 9223372036854775817
    big.lot_count  = 1;
    RederiveTokens(big);
    const std::vector<unsigned char> bmeta = BuildScalarNotePairIcuMetadata(big);
    const std::string bs(bmeta.begin(), bmeta.end());
    BOOST_CHECK(bs.find("9223372036854775813") != std::string::npos); // fixing_ref decimal
    BOOST_CHECK(bs.find("9223372036854775817") != std::string::npos); // vault_im decimal
}

BOOST_AUTO_TEST_CASE(record_validation)
{
    // Small N so the record is light; re-derive tokens for the reduced lot_count.
    ScalarNotePairTerms terms = ExampleTerms();
    terms.lot_count = 3;
    RederiveTokens(terms);

    const uint256 pair_id = ComputeScalarNotePairId(terms);
    const uint256 issue = Bytes32(0xDD);
    const Txid issue_txid = Txid::FromUint256(issue);

    auto make_record = [&]() {
        ScalarNotePairRecord r;
        r.pair_id = pair_id;
        r.terms = terms;
        r.register_long_txid = Bytes32(0xA1);
        r.register_short_txid = Bytes32(0xA2);
        r.issue_txid = issue;
        r.long_icu_outpoint = COutPoint(issue_txid, 0);
        r.short_icu_outpoint = COutPoint(issue_txid, 1);
        for (uint32_t i = 0; i < terms.lot_count; ++i) r.lot_vaults.emplace_back(issue_txid, 2 + i);
        return r;
    };

    std::string err;
    BOOST_REQUIRE(ValidateScalarNotePairRecord(make_record(), &pair_id, err));

    auto reject = [&](auto mutate) {
        ScalarNotePairRecord r = make_record();
        mutate(r);
        std::string e;
        BOOST_CHECK(!ValidateScalarNotePairRecord(r, &pair_id, e));
        BOOST_CHECK(!e.empty());
    };

    reject([](ScalarNotePairRecord& r){ r.pair_id = Bytes32(0x00); });            // id mismatch
    reject([](ScalarNotePairRecord& r){ r.issue_txid = uint256{}; });             // null issue
    reject([](ScalarNotePairRecord& r){ r.register_long_txid = uint256{}; });     // unregistered L
    reject([](ScalarNotePairRecord& r){ r.register_short_txid = uint256{}; });    // unregistered S
    reject([&](ScalarNotePairRecord& r){ r.lot_vaults.pop_back(); });             // wrong count
    reject([&](ScalarNotePairRecord& r){ r.lot_vaults.back() = r.lot_vaults.front(); }); // dup vault
    reject([&](ScalarNotePairRecord& r){ r.lot_vaults.back() = COutPoint(Txid::FromUint256(Bytes32(0xEE)), 9); }); // vault not from issue tx
    reject([&](ScalarNotePairRecord& r){ r.long_icu_outpoint = COutPoint(Txid::FromUint256(Bytes32(0xEE)), 0); }); // ICU not from issue tx
    reject([&](ScalarNotePairRecord& r){ r.short_icu_outpoint = r.long_icu_outpoint; }); // identical ICUs
    // A vault outpoint colliding with an ICU outpoint is rejected (dup).
    reject([&](ScalarNotePairRecord& r){ r.lot_vaults.back() = r.long_icu_outpoint; });
    // n == NULL_INDEX is not a valid output index even when the hash matches issue_txid.
    reject([&](ScalarNotePairRecord& r){ r.long_icu_outpoint = COutPoint(issue_txid, COutPoint::NULL_INDEX); });
    reject([&](ScalarNotePairRecord& r){ r.short_icu_outpoint = COutPoint(issue_txid, COutPoint::NULL_INDEX); });
    reject([&](ScalarNotePairRecord& r){ r.lot_vaults.back() = COutPoint(issue_txid, COutPoint::NULL_INDEX); });

    // Wrong expected_key is rejected even when the record is internally consistent.
    {
        ScalarNotePairRecord r = make_record();
        const uint256 wrong = Bytes32(0x01);
        std::string e;
        BOOST_CHECK(!ValidateScalarNotePairRecord(r, &wrong, e));
    }
}

BOOST_AUTO_TEST_CASE(issuance_build_and_verify)
{
    ScalarNotePairTerms terms = ExampleTerms();
    terms.lot_count = 2;
    RederiveTokens(terms);
    const uint256 pair_id = ComputeScalarNotePairId(terms);
    const uint32_t N = terms.lot_count;
    const uint64_t needed = static_cast<uint64_t>(N) * terms.vault_im;

    const CScript succL = P2TRFill(0x10), succS = P2TRFill(0x11), issuer = P2TRFill(0x12), change = P2TRFill(0x13);

    auto make_inputs = [&]() {
        ScalarNotePairIssuanceInputs in;
        in.long_icu  = IcuInput(0xF0, 0, terms.long_token_id,  N, "LTK");
        in.short_icu = IcuInput(0xF0, 1, terms.short_token_id, N, "STK");
        ScalarFundedInput coll;
        coll.outpoint = COutPoint(Txid::FromUint256(Bytes32(0xF1)), 0);
        coll.txout = AssetOut(P2TRFill(0x03), terms.collateral_asset_id, needed, /*nValue=*/1000); // exact → no C change
        in.collateral_inputs.push_back(coll);
        ScalarFundedInput nat;
        nat.outpoint = COutPoint(Txid::FromUint256(Bytes32(0xF2)), 0);
        nat.txout = CTxOut(CAmount{10'000'000}, P2TRFill(0x04));
        in.native_inputs.push_back(nat);
        return in;
    };

    // Happy path: atomic build → verifier accepts; structure is exactly as specified.
    {
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE_MESSAGE(BuildScalarNotePairIssuance(terms, pair_id, make_inputs(), succL, succS, issuer, change,
                              /*vault_native_sats=*/1000, /*fee=*/1000, /*dust=*/546, mtx, err), err);
        BOOST_CHECK_EQUAL(mtx.vout.size(), 2u + 2u + N + 1u); // 2 ICU + 2 mint + N vaults + native change
        const CTransaction tx{mtx};
        std::string verr;
        BOOST_CHECK_MESSAGE(ValidateScalarNotePairIssuanceTx(terms, pair_id, tx, verr), verr);

        // ICU successors reuse the spent vExt byte-identically (no governance mutation).
        BOOST_CHECK(mtx.vout[0].vExt == MakeIcuReg(terms.long_token_id, N, "LTK"));
        BOOST_CHECK(mtx.vout[1].vExt == MakeIcuReg(terms.short_token_id, N, "STK"));
        // Mints: exactly N L and N S to the issuer.
        BOOST_CHECK(mtx.vout[2].AssetID() == terms.long_token_id  && mtx.vout[2].AssetAmount() == uint64_t{N});
        BOOST_CHECK(mtx.vout[3].AssetID() == terms.short_token_id && mtx.vout[3].AssetAmount() == uint64_t{N});
        // Vaults: AssetTag(C, vault_im) at each derived vault spk.
        for (uint32_t i = 0; i < N; ++i) {
            const auto lot = DeriveScalarNoteLot(terms, pair_id, i);
            const CTxOut& v = mtx.vout[4 + i];
            BOOST_CHECK(v.scriptPubKey == lot.vault_spk);
            BOOST_CHECK(v.AssetID() == terms.collateral_asset_id && v.AssetAmount() == terms.vault_im);
        }
    }

    // Build-side negatives.
    auto build_fails = [&](auto tweak) {
        ScalarNotePairIssuanceInputs in = make_inputs();
        tweak(in);
        CMutableTransaction mtx; std::string err;
        BOOST_CHECK(!BuildScalarNotePairIssuance(terms, pair_id, in, succL, succS, issuer, change, 1000, 1000, 546, mtx, err));
    };
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(Bytes32(0xDE), N, "LTK"); }); // wrong L id (consistency check)
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N + 1, "LTK"); }); // cap != N
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED | assets::BURN_ALLOWED); }); // BURN
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED, /*quorum=*/100); }); // quorum != 0
    // Bearer-coupon profile: any extra policy bit / kyc / tfr / WRAP / restrictive families is rejected.
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED | assets::KYC_REQUIRED); }); // extra policy bit
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED | assets::BURN_REQUIRE_ICU); });
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED, 0, 0, assets::SPK_DEFAULT_ALLOWED, /*kyc=*/1); });
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED, 0, 0, assets::SPK_DEFAULT_ALLOWED, 0, /*tfr=*/1); });
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED, 0, 0, assets::SPK_DEFAULT_ALLOWED, 0, 0, assets::WRAP_REQUIRED); });
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.long_icu.txout.vExt = MakeIcuReg(terms.long_token_id, N, "LTK", assets::MINT_ALLOWED, 0, 0, assets::SPK_HOLDER_ONLY); }); // no P2TR
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.collateral_inputs[0].txout = AssetOut(P2TRFill(0x03), terms.collateral_asset_id, needed - 1, 1000); }); // insufficient C
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.collateral_inputs[0].txout = AssetOut(P2TRFill(0x03), Bytes32(0x99), needed, 1000); }); // wrong C asset
    build_fails([&](ScalarNotePairIssuanceInputs& in){ in.native_inputs.clear(); }); // can't cover bonds+dust+fee

    // A mint destination outside the coupon family set (P2PKH) is rejected up front (would otherwise
    // fail consensus with asset-spk-not-allowed on the d>0 mint).
    {
        const CScript p2pkh = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x07) << OP_EQUALVERIFY << OP_CHECKSIG;
        CMutableTransaction mtx; std::string err;
        BOOST_CHECK(!BuildScalarNotePairIssuance(terms, pair_id, make_inputs(), succL, succS, /*issuer=*/p2pkh, change, 1000, 1000, 546, mtx, err));
    }

    // Verifier negatives: mutate a valid tx so the coupling breaks.
    {
        CMutableTransaction good; std::string err;
        BOOST_REQUIRE(BuildScalarNotePairIssuance(terms, pair_id, make_inputs(), succL, succS, issuer, change, 1000, 1000, 546, good, err));
        auto verify_fails = [&](auto tweak) {
            CMutableTransaction m = good; tweak(m);
            const CTransaction tx{m}; std::string e;
            BOOST_CHECK(!ValidateScalarNotePairIssuanceTx(terms, pair_id, tx, e));
        };
        verify_fails([&](CMutableTransaction& m){ m.vout.erase(m.vout.begin() + 4); });                                  // drop a vault
        verify_fails([&](CMutableTransaction& m){ m.vout[2].vExt = assets::BuildAssetTagTlv(terms.long_token_id, N + 1); }); // over-mint L
        verify_fails([&](CMutableTransaction& m){ m.vout[0].vExt.clear(); });                                            // drop L successor
        verify_fails([&](CMutableTransaction& m){ m.vout[5].scriptPubKey = m.vout[4].scriptPubKey; });                   // duplicate vault spk
        // Two L-mint outputs whose amounts wrap uint64 back to N must NOT pass the output-sum invariant.
        verify_fails([&](CMutableTransaction& m){
            const uint64_t half = uint64_t{1} << 63;
            m.vout[2].vExt = assets::BuildAssetTagTlv(terms.long_token_id, half);
            CTxOut extra(546, issuer); extra.vExt = assets::BuildAssetTagTlv(terms.long_token_id, half + N); // half+(half+N)=2^64+N → wraps to N
            m.vout.push_back(extra);
        });
    }

    // Native-collateral variant: vaults are native (nValue == vault_im, no AssetTag); no collateral inputs.
    {
        ScalarNotePairTerms nt = ExampleTerms();
        nt.collateral_asset_id = uint256{};
        nt.vault_im = 100000;
        nt.lot_count = 2;
        RederiveTokens(nt);
        const uint256 npid = ComputeScalarNotePairId(nt);
        ScalarNotePairIssuanceInputs in;
        in.long_icu  = IcuInput(0xE0, 0, nt.long_token_id,  2, "LTK");
        in.short_icu = IcuInput(0xE0, 1, nt.short_token_id, 2, "STK");
        ScalarFundedInput nat; nat.outpoint = COutPoint(Txid::FromUint256(Bytes32(0xE2)), 0);
        nat.txout = CTxOut(CAmount{10'000'000}, P2TRFill(0x04));
        in.native_inputs.push_back(nat);
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE_MESSAGE(BuildScalarNotePairIssuance(nt, npid, in, succL, succS, issuer, change,
                              /*vault_native_sats=*/0, 1000, 546, mtx, err), err);
        const CTransaction tx{mtx}; std::string verr;
        BOOST_CHECK_MESSAGE(ValidateScalarNotePairIssuanceTx(nt, npid, tx, verr), verr);
        for (uint32_t i = 0; i < 2; ++i) {
            const auto lot = DeriveScalarNoteLot(nt, npid, i);
            const CTxOut& v = mtx.vout[4 + i];
            BOOST_CHECK(v.scriptPubKey == lot.vault_spk);
            BOOST_CHECK(!v.HasAssetTLV());
            BOOST_CHECK_EQUAL(static_cast<uint64_t>(v.nValue), nt.vault_im);
        }
    }
}

BOOST_AUTO_TEST_CASE(pot_leaf_execution)
{
    const uint256 L = Bytes32(0x11);
    const CScript sink = CScript() << OP_1 << std::vector<unsigned char>(32, 0xA0);
    const CScript other = CScript() << OP_1 << std::vector<unsigned char>(32, 0xCC);
    const CScript leaf = BuildScalarPotLeaf(L, sink);

    BOOST_CHECK(RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(sink, L, 1)})));                       // 1 L → sink
    BOOST_CHECK(RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(sink, L, 1), CTxOut(1000, sink)})));   // extra ok
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({})));                                          // nothing
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(sink, Bytes32(0x22), 1)})));          // wrong token
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(other, L, 1)})));                     // wrong sink
    BOOST_CHECK(!RunCovenantLeaf(leaf, TxWithOutputs({AssetOut(sink, L, 2)})));                      // amount != 1
}

BOOST_AUTO_TEST_CASE(redemption_build)
{
    const ScalarNotePairTerms terms = ExampleTerms(); // asset collateral
    const uint256 pair_id = ComputeScalarNotePairId(terms);
    const CScript holder = P2TRFill(0x20);
    const uint64_t leg = 900000;

    auto pot_for = [&](uint32_t i) {
        ScalarRedemptionPot rp; rp.lot_index = i;
        const auto lot = DeriveScalarNoteLot(terms, pair_id, i);
        rp.pot.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x40 + i)), 0);
        rp.pot.txout = AssetOut(lot.long_pot_spk, terms.collateral_asset_id, leg, 546);
        return rp;
    };
    auto token_in = [&](uint64_t units) {
        ScalarFundedInput ti; ti.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x50)), 0);
        ti.txout = AssetOut(holder, terms.long_token_id, units, 546);
        return ti;
    };
    ScalarFundedInput nat; nat.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x60)), 0);
    nat.txout = CTxOut(CAmount{1'000'000}, holder);

    // Happy: redeem 2 long pots with 5 L (m=5, k=2 → 3 change).
    {
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE_MESSAGE(BuildScalarNoteRedemption(terms, pair_id, /*redeem_long=*/true,
                              {pot_for(0), pot_for(1)}, {token_in(5)}, {nat}, holder, 1000, 546, mtx, err), err);
        BOOST_CHECK_EQUAL(mtx.vin.size(), 2u + 1u + 1u);
        BOOST_CHECK_EQUAL(mtx.vout.size(), 5u); // 2 sinks + token change + C payout + native sweep
        for (uint32_t i = 0; i < 2; ++i) {
            const auto lot = DeriveScalarNoteLot(terms, pair_id, i);
            BOOST_CHECK(mtx.vout[i].scriptPubKey == lot.long_sink_spk);
            BOOST_CHECK(mtx.vout[i].AssetID() == terms.long_token_id && mtx.vout[i].AssetAmount() == uint64_t{1});
        }
        bool change = false, payout = false;
        for (const auto& o : mtx.vout) {
            if (o.AssetID() == terms.long_token_id && o.AssetAmount() == uint64_t{3}) change = true;
            if (o.AssetID() == terms.collateral_asset_id && o.AssetAmount() == uint64_t{2 * leg}) payout = true;
        }
        BOOST_CHECK(change);
        BOOST_CHECK(payout);
    }

    auto fails = [&](auto setup) {
        std::vector<ScalarRedemptionPot> pots; std::vector<ScalarFundedInput> toks, nats;
        setup(pots, toks, nats);
        CMutableTransaction mtx; std::string err;
        BOOST_CHECK(!BuildScalarNoteRedemption(terms, pair_id, /*redeem_long=*/true, pots, toks, nats, holder, 1000, 546, mtx, err));
    };
    using PV = std::vector<ScalarRedemptionPot>; using FV = std::vector<ScalarFundedInput>;
    // Wrong side: a SHORT pot offered to a long redemption.
    fails([&](PV& pots, FV& toks, FV& nats){
        ScalarRedemptionPot rp; rp.lot_index = 0; const auto lot = DeriveScalarNoteLot(terms, pair_id, 0);
        rp.pot.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x41)), 0);
        rp.pot.txout = AssetOut(lot.short_pot_spk, terms.collateral_asset_id, leg, 546);
        pots.push_back(rp); toks.push_back(token_in(2)); nats.push_back(nat);
    });
    // Wrong token (S presented for a long redemption).
    fails([&](PV& pots, FV& toks, FV& nats){
        pots.push_back(pot_for(0));
        ScalarFundedInput ti; ti.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x51)), 0);
        ti.txout = AssetOut(holder, terms.short_token_id, 5, 546);
        toks.push_back(ti); nats.push_back(nat);
    });
    fails([&](PV& pots, FV& toks, FV& nats){ pots = {pot_for(0), pot_for(1)}; toks = {token_in(1)}; nats = {nat}; }); // insufficient
    // Huge dust must be rejected by the aggregation guard, not overflow CAmount (2 outputs * MAX_MONEY).
    {
        CMutableTransaction mtx; std::string err;
        BOOST_CHECK(!BuildScalarNoteRedemption(terms, pair_id, /*redeem_long=*/true,
                    {pot_for(0), pot_for(1)}, {token_in(5)}, {nat}, holder, /*fee=*/1000, /*dust=*/MAX_MONEY, mtx, err));
    }
    fails([&](PV& pots, FV& toks, FV& nats){ pots = {pot_for(0), pot_for(0)}; toks = {token_in(5)}; nats = {nat}; });  // dup lot
    fails([&](PV& pots, FV& toks, FV& nats){ // pot carries the wrong collateral asset
        ScalarRedemptionPot rp; rp.lot_index = 0; const auto lot = DeriveScalarNoteLot(terms, pair_id, 0);
        rp.pot.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x42)), 0);
        rp.pot.txout = AssetOut(lot.long_pot_spk, Bytes32(0x99), leg, 546);
        pots.push_back(rp); toks.push_back(token_in(2)); nats.push_back(nat);
    });

    // Native-collateral variant: pot is native, no C-payout output (folds into the native sweep).
    {
        ScalarNotePairTerms nt = ExampleTerms(); nt.collateral_asset_id = uint256{}; nt.vault_im = 100000; RederiveTokens(nt);
        const uint256 npid = ComputeScalarNotePairId(nt);
        const auto lot = DeriveScalarNoteLot(nt, npid, 0);
        ScalarRedemptionPot rp; rp.lot_index = 0;
        rp.pot.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x70)), 0);
        rp.pot.txout = CTxOut(CAmount{500000}, lot.long_pot_spk); // native pot
        ScalarFundedInput ti; ti.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x71)), 0);
        ti.txout = AssetOut(holder, nt.long_token_id, 1, 546);
        ScalarFundedInput n2; n2.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x72)), 0); n2.txout = CTxOut(CAmount{10000}, holder);
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE_MESSAGE(BuildScalarNoteRedemption(nt, npid, /*redeem_long=*/true, {rp}, {ti}, {n2}, holder, 1000, 546, mtx, err), err);
        BOOST_CHECK_EQUAL(mtx.vout.size(), 2u); // 1 sink + native sweep (m==k → no token change; native → no C payout)
        BOOST_CHECK(mtx.vout[0].scriptPubKey == lot.long_sink_spk);
        BOOST_CHECK(mtx.vout[0].AssetID() == nt.long_token_id && mtx.vout[0].AssetAmount() == uint64_t{1});
        BOOST_CHECK(!mtx.vout[1].HasAssetTLV()); // the reclaimed collateral is the native sweep
    }
}

BOOST_AUTO_TEST_CASE(unwind_build)
{
    const ScalarNotePairTerms terms = ExampleTerms(); // asset collateral, vault_im = 1'000'000
    const uint256 pair_id = ComputeScalarNotePairId(terms);
    const CScript holder = P2TRFill(0x30);
    const auto lot = DeriveScalarNoteLot(terms, pair_id, 0);

    auto vault_in = [&](const uint256& cid, uint64_t amt) {
        ScalarFundedInput v; v.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x80)), 0);
        v.txout = AssetOut(lot.vault_spk, cid, amt, 1000);
        return v;
    };
    auto tok = [&](uint8_t h, const uint256& id, uint64_t units) {
        ScalarFundedInput t; t.outpoint = COutPoint(Txid::FromUint256(Bytes32(h)), 0);
        t.txout = AssetOut(holder, id, units, 546);
        return t;
    };
    ScalarFundedInput nat; nat.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x83)), 0);
    nat.txout = CTxOut(CAmount{1'000'000}, holder);

    // Happy: present 1 L + 1 S → retire both, reclaim full collateral.
    {
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE_MESSAGE(BuildScalarUnwind(terms, pair_id, 0, vault_in(terms.collateral_asset_id, terms.vault_im),
                              {tok(0x81, terms.long_token_id, 1)}, {tok(0x82, terms.short_token_id, 1)}, {nat},
                              holder, 1000, 546, mtx, err), err);
        BOOST_CHECK_EQUAL(mtx.vout.size(), 4u); // L sink + S sink + C payout + native sweep (no token change)
        BOOST_CHECK(mtx.vout[0].scriptPubKey == lot.long_sink_spk  && mtx.vout[0].AssetID() == terms.long_token_id  && mtx.vout[0].AssetAmount() == uint64_t{1});
        BOOST_CHECK(mtx.vout[1].scriptPubKey == lot.short_sink_spk && mtx.vout[1].AssetID() == terms.short_token_id && mtx.vout[1].AssetAmount() == uint64_t{1});
        bool payout = false;
        for (const auto& o : mtx.vout) if (o.AssetID() == terms.collateral_asset_id && o.AssetAmount() == terms.vault_im) payout = true;
        BOOST_CHECK(payout);
        // The vault is spent via the unwind leaf with no signature: witness == [unwind_leaf, control],
        // where control is exactly the {settle, unwind} taptree's control block for the unwind leaf.
        BOOST_REQUIRE_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 2u);
        const std::vector<unsigned char> uleaf(lot.unwind_leaf.begin(), lot.unwind_leaf.end());
        BOOST_CHECK(mtx.vin[0].scriptWitness.stack[0] == uleaf);
        TaprootBuilder vb = CreateScalarVaultBuilder(lot.settle_leaf, lot.unwind_leaf);
        BOOST_REQUIRE(vb.IsComplete());
        const auto sd = vb.GetSpendData();
        const auto cit = sd.scripts.find({uleaf, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
        BOOST_REQUIRE(cit != sd.scripts.end() && !cit->second.empty());
        BOOST_CHECK(mtx.vin[0].scriptWitness.stack[1] == *cit->second.begin());
    }

    // Token change on both sides (2 L, 2 S).
    {
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE(BuildScalarUnwind(terms, pair_id, 0, vault_in(terms.collateral_asset_id, terms.vault_im),
                      {tok(0x81, terms.long_token_id, 2)}, {tok(0x82, terms.short_token_id, 2)}, {nat}, holder, 1000, 546, mtx, err));
        bool lchg = false, schg = false;
        for (const auto& o : mtx.vout) {
            if (o.scriptPubKey == holder && o.AssetID() == terms.long_token_id  && o.AssetAmount() == uint64_t{1}) lchg = true;
            if (o.scriptPubKey == holder && o.AssetID() == terms.short_token_id && o.AssetAmount() == uint64_t{1}) schg = true;
        }
        BOOST_CHECK(lchg && schg);
    }

    // Negatives.
    auto fails = [&](const ScalarFundedInput& v, const std::vector<ScalarFundedInput>& L,
                     const std::vector<ScalarFundedInput>& S, CAmount d = 546) {
        CMutableTransaction mtx; std::string err;
        BOOST_CHECK(!BuildScalarUnwind(terms, pair_id, 0, v, L, S, {nat}, holder, 1000, d, mtx, err));
    };
    // Vault at the wrong spk.
    {
        ScalarFundedInput v; v.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x84)), 0);
        v.txout = AssetOut(P2TRFill(0xEE), terms.collateral_asset_id, terms.vault_im, 1000);
        fails(v, {tok(0x81, terms.long_token_id, 1)}, {tok(0x82, terms.short_token_id, 1)});
    }
    fails(vault_in(terms.collateral_asset_id, terms.vault_im), {}, {tok(0x82, terms.short_token_id, 1)}); // missing L
    fails(vault_in(terms.collateral_asset_id, terms.vault_im), {tok(0x81, terms.long_token_id, 1)}, {}); // missing S
    fails(vault_in(terms.collateral_asset_id, terms.vault_im - 1), {tok(0x81, terms.long_token_id, 1)}, {tok(0x82, terms.short_token_id, 1)}); // wrong collateral amount
    fails(vault_in(Bytes32(0x99), terms.vault_im), {tok(0x81, terms.long_token_id, 1)}, {tok(0x82, terms.short_token_id, 1)}); // wrong collateral asset
    fails(vault_in(terms.collateral_asset_id, terms.vault_im), {tok(0x81, terms.long_token_id, 1)}, {tok(0x82, terms.short_token_id, 1)}, /*dust=*/MAX_MONEY); // dust overflow guard

    // Native-collateral variant: vault is native (nValue == vault_im), reclaimed via the sweep.
    {
        ScalarNotePairTerms nt = ExampleTerms(); nt.collateral_asset_id = uint256{}; nt.vault_im = 500000; RederiveTokens(nt);
        const uint256 npid = ComputeScalarNotePairId(nt);
        const auto nlot = DeriveScalarNoteLot(nt, npid, 0);
        ScalarFundedInput v; v.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x90)), 0);
        v.txout = CTxOut(CAmount{500000}, nlot.vault_spk); // native vault
        ScalarFundedInput L; L.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x91)), 0); L.txout = AssetOut(holder, nt.long_token_id, 1, 546);
        ScalarFundedInput S; S.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x92)), 0); S.txout = AssetOut(holder, nt.short_token_id, 1, 546);
        ScalarFundedInput n2; n2.outpoint = COutPoint(Txid::FromUint256(Bytes32(0x93)), 0); n2.txout = CTxOut(CAmount{10000}, holder);
        CMutableTransaction mtx; std::string err;
        BOOST_REQUIRE_MESSAGE(BuildScalarUnwind(nt, npid, 0, v, {L}, {S}, {n2}, holder, 1000, 546, mtx, err), err);
        BOOST_CHECK_EQUAL(mtx.vout.size(), 3u); // L sink + S sink + native sweep (no C payout)
        for (const auto& o : mtx.vout) BOOST_CHECK(!(o.AssetID() && *o.AssetID() == nt.long_token_id && o.scriptPubKey == holder)); // no token change
    }
}

BOOST_AUTO_TEST_CASE(frozen_vectors)
{
    // Canonical example (ExampleTerms is fully fixed) frozen so the descriptor/id/derivations cannot
    // silently drift. Regenerate ONLY with a deliberate, reviewed change to the byte layout or tags.
    const ScalarNotePairTerms t = ExampleTerms();
    const std::vector<unsigned char> d = SerializeScalarNotePairDescriptor(t);
    const uint256 pair_id = ComputeScalarNotePairId(t);
    const ScalarNoteLot l0 = DeriveScalarNoteLot(t, pair_id, 0);
    const ScalarNoteLot l1 = DeriveScalarNoteLot(t, pair_id, 1);

    BOOST_CHECK_EQUAL(HexStr(d),
        "01000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10700000015cd5b0700000000f0490200544a0200010064646464646464646464646464646464646464646464646464646464646464645f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f55550300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c040420f000000000088215b2d83a26a388dd45273a85f8a8eca0a61feba200adb922a7c651c0e48749ab32c0b04f917840f736bdf5197d43aa069e9731fd691c70e019ab49d72d13964000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    BOOST_CHECK_EQUAL(HexStr(pair_id), "216538ad8def8c341a88a50964084c3369a278162554c0826e66591f672643fe");
    BOOST_CHECK_EQUAL(HexStr(l0.long_sink_key),  "617200a9c1222b6c64386587070dffee9e19dc1f4d2dd3e6d2150c35d79b274a");
    BOOST_CHECK_EQUAL(HexStr(l0.short_sink_key), "48ae55e58dfdeab65fdd001e01d3d1aef32b0a289c954ee1108510d7dfd64268");
    BOOST_CHECK_EQUAL(HexStr(l0.long_pot_key),   "c977df0332a4127b04c8524482aefb505d0377ddf7aa0b8ae241d7d57d68daac");
    BOOST_CHECK_EQUAL(HexStr(l0.short_pot_key),  "6f47731dee0fd688fbb415021648b1e73602500624624aa885ff62b55f05f144");
    BOOST_CHECK_EQUAL(HexStr(l0.settle_leaf),
        "200f48144bf46570fdff45e069d0cea4e78c457ebaefd98a388f63fa0afdacdc6075010103544a02b175010020a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a104070000000815cd5b070000000004f04902000100020100206464646464646464646464646464646464646464646464646464646464646464205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0455550300010020c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00840420f000000000020c977df0332a4127b04c8524482aefb505d0377ddf7aa0b8ae241d7d57d68daac206f47731dee0fd688fbb415021648b1e73602500624624aa885ff62b55f05f144b9");
    BOOST_CHECK_EQUAL(HexStr(l1.long_sink_key),  "0f7b653e56192f4922fa3f5a05f1c8b83d9a9ce2e91d9916f89d431e7fa4d34c");
    BOOST_CHECK_EQUAL(HexStr(l1.short_sink_key), "520dc0d8f84d4a57d198358fc4f415751da59a3dc7f6ffa5dd72f06e49d3548a");
    BOOST_CHECK_EQUAL(HexStr(l1.long_pot_key),   "ab5bbeb6d1aabd466dbc7024db4e9dfcb82ec841afa1857d38eeb1abb8ced1f1");
    BOOST_CHECK_EQUAL(HexStr(l1.short_pot_key),  "71e49bf4c2fec234c9139c33eb917652dda8c2f4f2ea9abec8249497f13c3115");
    BOOST_CHECK_EQUAL(HexStr(l1.settle_leaf),
        "20dd975a1e2d6ebe03c03ab5f9abc03584ffdb87d3c52b24bfc687c893b919430075010103544a02b175010020a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a104070000000815cd5b070000000004f04902000100020100206464646464646464646464646464646464646464646464646464646464646464205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0455550300010020c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00840420f000000000020ab5bbeb6d1aabd466dbc7024db4e9dfcb82ec841afa1857d38eeb1abb8ced1f12071e49bf4c2fec234c9139c33eb917652dda8c2f4f2ea9abec8249497f13c3115b9");
    BOOST_CHECK_EQUAL(HexStr(l0.unwind_leaf),
        "20a83e19340f4398b92a6694f08dc3b98aa2dfdcad5b6be0cef4e35a9e644c46d22088215b2d83a26a388dd45273a85f8a8eca0a61feba200adb922a7c651c0e4874080100000000000000b869204aa6e7326b73af88718eaad288b91b4ecbef27ea3fa153255776b68bdffe021d209ab32c0b04f917840f736bdf5197d43aa069e9731fd691c70e019ab49d72d139080100000000000000b8");
    BOOST_CHECK_EQUAL(HexStr(l0.vault_spk),   "51205f059a9af5aba6a826aed247de6d4ad7009e76d67651cecc644c47eab4c28c89");
    BOOST_CHECK_EQUAL(HexStr(l1.unwind_leaf),
        "207e59d82eb1a6194239c6f6f737388ec36839e74037abdd3abde0df16fe182faa2088215b2d83a26a388dd45273a85f8a8eca0a61feba200adb922a7c651c0e4874080100000000000000b86920e291825292cdc662b6f137a6dbd1c4a8bd90f119210b6d02090a55d37efcb30f209ab32c0b04f917840f736bdf5197d43aa069e9731fd691c70e019ab49d72d139080100000000000000b8");
    BOOST_CHECK_EQUAL(HexStr(l1.vault_spk),   "5120d81191a4a720459ffcbd53f4105e4ff33e94e663a9c6f0179b7c61f9d08bb713");
}

BOOST_AUTO_TEST_SUITE_END()
