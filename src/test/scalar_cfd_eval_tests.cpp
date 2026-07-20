// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <assets/asset.h>                  // assets::OutExtType::ASSET_TAG
#include <consensus/difficulty_cfd.h>      // MIN_SETTLE_OUTPUT
#include <consensus/scalar_cfd.h>
#include <consensus/scalar_cfd_snapshot.h>
#include <crypto/common.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_eval_tests, BasicTestingSetup)

namespace {
using valtype = std::vector<unsigned char>;

valtype LE16(uint16_t v) { valtype b(2); WriteLE16(b.data(), v); return b; }
valtype LE32(uint32_t v) { valtype b(4); WriteLE32(b.data(), v); return b; }
valtype LE64(uint64_t v) { valtype b(8); WriteLE64(b.data(), v); return b; }
valtype Bytes(size_t n, unsigned char fill) { return valtype(n, fill); }
valtype ToVec(const uint256& u) { return valtype(u.begin(), u.end()); }
uint256 U256(uint8_t b) { return uint256{std::vector<unsigned char>(32, b)}; }
uint256 A256(uint64_t v) { return ArithToUint256(arith_uint256(v)); } // small integer as a scalar

constexpr uint32_t Q16(uint32_t lambda) { return lambda * static_cast<uint32_t>(SCALARCFD_LAMBDA_SCALE); }
const uint64_t MIN = static_cast<uint64_t>(MIN_SETTLE_OUTPUT);
constexpr unsigned int ACTIVE_FLAGS = SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_SCALAR_CFD;

bool IsTruthy(const valtype& v)
{
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] != 0) return !(i == v.size() - 1 && v[i] == 0x80); // negative zero is false
    }
    return false;
}

CScript P2TR(const valtype& key) { CScript s; s << OP_1 << key; return s; }

// An ASSET_TAG output TLV (asset_id + amount), as ConnectBlock would carry on an asset-bearing
// output. The native covenant must reject any output carrying one.
valtype AssetTag(const uint256& asset_id, uint64_t amount)
{
    valtype tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(40); // compact size for 32 + 8
    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
    unsigned char buf[8];
    WriteLE64(buf, amount);
    tlv.insert(tlv.end(), buf, buf + 8);
    return tlv;
}

// The committed terms of a settlement leaf, all valid + native by default. K (strike) and the
// resolved scalar X are supplied per test as small integers.
struct Terms {
    uint8_t  source_type   = 0;            // ISSUER_PUBLISHED
    uint256  underlying    = U256(0x22);
    uint32_t feed_id       = 7;
    uint64_t fixing_ref    = 1000;
    uint32_t deadline      = 900000;
    uint8_t  payoff_mode   = 0;            // STRIKE
    uint16_t scalar_format = 1;            // SCALAR_FORMAT_RAW_U256_LE
    uint256  strike        = A256(100);
    uint256  fallback      = U256(0x44);
    uint32_t lambda_q      = Q16(1);
    uint8_t  loss_dir      = 0;            // long
    uint256  collateral    = uint256{};    // NATIVE_SENTINEL (all zero)
    uint64_t vault_im      = 1'000'000;
    valtype  owner         = Bytes(32, 0x55);
    valtype  cp            = Bytes(32, 0x66);
};

// Push the 16 canonical operands (contract_id + settle_lock_height are dropped before the opcode
// in a real leaf; the eval only sees these) followed by the settlement opcode.
CScript BuildScript(const Terms& t)
{
    CScript s;
    s << valtype{0x01};                  // template_version
    s << valtype{t.source_type};
    s << ToVec(t.underlying);
    s << LE32(t.feed_id);
    s << LE64(t.fixing_ref);
    s << LE32(t.deadline);
    s << valtype{t.payoff_mode};
    s << LE16(t.scalar_format);
    s << ToVec(t.strike);
    s << ToVec(t.fallback);
    s << LE32(t.lambda_q);
    s << valtype{t.loss_dir};
    s << ToVec(t.collateral);
    s << LE64(t.vault_im);
    s << t.owner;
    s << t.cp;
    s << OP_SCALAR_CFD_SETTLE;
    return s;
}

ScalarFixingKey KeyOf(const Terms& t) { return ScalarFixingKey{t.source_type, t.underlying, t.feed_id, t.fixing_ref}; }

void AddEntry(ScalarFixingSnapshot& snap, const Terms& t, uint64_t X)
{
    snap.Add(KeyOf(t), ResolvedScalar{A256(X), t.scalar_format, /*is_fallback=*/false});
}

ScalarCfdPayout Expect(const Terms& t, uint64_t X)
{
    const ScalarLossDenominator d = t.payoff_mode == 1 ? ScalarLossDenominator::REALIZED : ScalarLossDenominator::STRIKE;
    ScalarCfdPayout p;
    BOOST_REQUIRE(ComputeScalarCfdPayout(UintToArith256(t.strike), arith_uint256(X), d, t.lambda_q,
                                         t.vault_im, t.loss_dir == 1, MIN, p));
    return p;
}

CMutableTransaction TxFor(const ScalarCfdPayout& p, const valtype& owner, const valtype& cp)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    if (p.payout_owner > 0) mtx.vout.emplace_back(static_cast<CAmount>(p.payout_owner), P2TR(owner));
    if (p.payout_cp > 0) mtx.vout.emplace_back(static_cast<CAmount>(p.payout_cp), P2TR(cp));
    return mtx;
}

// Run a script under EvalScript with a snapshot-bearing checker; return the error (OK on truthy).
ScriptError Run(const CScript& script, const CTransaction& tx, uint64_t input_amount,
                const ScalarFixingSnapshot* snap, unsigned int flags = ACTIVE_FLAGS, int witver = 1)
{
    std::vector<valtype> stack;
    ScriptExecutionData execdata;
    execdata.m_witness_version = witver;
    TransactionSignatureChecker checker(&tx, 0, static_cast<CAmount>(input_amount), MissingDataBehavior::FAIL,
                                        /*fixing=*/nullptr, snap);
    ScriptError err = SCRIPT_ERR_OK;
    const bool ok = EvalScript(stack, script, flags, checker, SigVersion::TAPSCRIPT, execdata, &err);
    if (!ok) return err;
    BOOST_CHECK_MESSAGE(!stack.empty() && IsTruthy(stack.back()), "opcode succeeded but left a falsy stack");
    return SCRIPT_ERR_OK;
}

// Asset-collateral variant: the checker carries the spent coin's asset tag (input binding) instead
// of a native amount; the snapshot carries the collateral policy (set per test via AddCollateralPolicy).
ScriptError RunAsset(const CScript& script, const CTransaction& tx,
                     std::optional<CovenantInputAsset> input_asset,
                     const ScalarFixingSnapshot* snap, unsigned int flags = ACTIVE_FLAGS)
{
    std::vector<valtype> stack;
    ScriptExecutionData execdata;
    execdata.m_witness_version = 1;
    TransactionSignatureChecker checker(&tx, 0, /*amount=*/0, MissingDataBehavior::FAIL,
                                        /*fixing=*/nullptr, snap, input_asset);
    ScriptError err = SCRIPT_ERR_OK;
    const bool ok = EvalScript(stack, script, flags, checker, SigVersion::TAPSCRIPT, execdata, &err);
    if (!ok) return err;
    BOOST_CHECK_MESSAGE(!stack.empty() && IsTruthy(stack.back()), "opcode succeeded but left a falsy stack");
    return SCRIPT_ERR_OK;
}

// Asset-tagged payout outputs: each non-zero leg -> nValue=dust (>= floor), vExt=AssetTag(C, leg).
CMutableTransaction TxForAsset(const ScalarCfdPayout& p, const valtype& owner, const valtype& cp,
                               const uint256& C, CAmount dust = static_cast<CAmount>(MIN))
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    if (p.payout_owner > 0) { CTxOut o(dust, P2TR(owner)); o.vExt = AssetTag(C, p.payout_owner); mtx.vout.push_back(o); }
    if (p.payout_cp > 0)    { CTxOut o(dust, P2TR(cp));    o.vExt = AssetTag(C, p.payout_cp);    mtx.vout.push_back(o); }
    return mtx;
}

ScalarCollateralPolicy CleanPolicy() { return ScalarCollateralPolicy{/*collateral_safe=*/true, 0, 0, 0}; }
} // namespace

// ---- Positive settlements -------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(native_partial_two_outputs)
{
    Terms t; t.strike = A256(100); // STRIKE long, X=90 -> cp=100000, owner=900000
    ScalarFixingSnapshot snap; AddEntry(snap, t, /*X=*/90);
    const auto p = Expect(t, 90);
    BOOST_CHECK_EQUAL(p.payout_cp, 100'000u);
    const CMutableTransaction mtx = TxFor(p, t.owner, t.cp);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(mtx), t.vault_im, &snap), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(native_flat_owner_only)
{
    Terms t; // X=K=100 -> flat -> owner keeps full, no cp output
    ScalarFixingSnapshot snap; AddEntry(snap, t, /*X=*/100);
    const auto p = Expect(t, 100);
    BOOST_CHECK_EQUAL(p.payout_owner, t.vault_im);
    BOOST_CHECK_EQUAL(p.payout_cp, 0u);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), t.vault_im, &snap), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(native_full_liquidation_cp_only)
{
    Terms t; t.lambda_q = Q16(10); // X=90, lambda 10 -> f_loss 1.0 -> cp=vault, no owner output
    ScalarFixingSnapshot snap; AddEntry(snap, t, /*X=*/90);
    const auto p = Expect(t, 90);
    BOOST_CHECK_EQUAL(p.payout_cp, t.vault_im);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), t.vault_im, &snap), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(realized_mode_partial)
{
    Terms t; t.payoff_mode = 1; // REALIZED, X=80 -> cp=250000
    ScalarFixingSnapshot snap; AddEntry(snap, t, /*X=*/80);
    const auto p = Expect(t, 80);
    BOOST_CHECK_EQUAL(p.payout_cp, 250'000u);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), t.vault_im, &snap), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(short_direction_partial)
{
    Terms t; t.loss_dir = 1; // short, X=110 -> loss -> cp=100000
    ScalarFixingSnapshot snap; AddEntry(snap, t, /*X=*/110);
    const auto p = Expect(t, 110);
    BOOST_CHECK_EQUAL(p.payout_cp, 100'000u);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), t.vault_im, &snap), SCRIPT_ERR_OK);
}

// ---- Resolution / context failures ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(missing_snapshot_is_context_error)
{
    Terms t;
    const CMutableTransaction mtx; // unused; fails before output binding
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(mtx), t.vault_im, /*snap=*/nullptr), SCRIPT_ERR_SCALARCFD_CONTEXT);
}

BOOST_AUTO_TEST_CASE(missing_entry_is_fixing_error)
{
    Terms t;
    ScalarFixingSnapshot snap; // entry under a DIFFERENT feed -> the leaf's key misses
    Terms other = t; other.feed_id = 999; AddEntry(snap, other, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_FIXING);
}

BOOST_AUTO_TEST_CASE(wrong_input_amount_is_amount_error)
{
    Terms t;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    const auto p = Expect(t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), t.vault_im + 1, &snap),
                      SCRIPT_ERR_SCALARCFD_AMOUNT);
}

BOOST_AUTO_TEST_CASE(missing_output_is_outputs_error)
{
    Terms t;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    const CMutableTransaction mtx{}; // correct input amount but no outputs
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(mtx), t.vault_im, &snap), SCRIPT_ERR_SCALARCFD_OUTPUTS);
}

// ---- Non-native (asset) collateral (Slice 4c) -----------------------------------------------

BOOST_AUTO_TEST_CASE(asset_collateral_settles)
{
    // C-collateralised long, X=90: cp gets 0.1, owner 0.9 of vault_im, both as AssetTag(C, leg).
    Terms t; t.collateral = U256(0x77);
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    snap.AddCollateralPolicy(t.collateral, CleanPolicy());
    const auto p = Expect(t, 90);
    const CovenantInputAsset in{t.collateral, t.vault_im};
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), CTransaction(TxForAsset(p, t.owner, t.cp, t.collateral)), in, &snap),
                      SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(asset_collateral_output_dust_tolerant)
{
    // nValue on an asset output need only be >= dust, not exact: a fatter native dust still settles.
    Terms t; t.collateral = U256(0x77);
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    snap.AddCollateralPolicy(t.collateral, CleanPolicy());
    const auto p = Expect(t, 90);
    const CovenantInputAsset in{t.collateral, t.vault_im};
    const auto mtx = TxForAsset(p, t.owner, t.cp, t.collateral, /*dust=*/static_cast<CAmount>(MIN) + 1000);
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), CTransaction(mtx), in, &snap), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(asset_collateral_no_resolved_policy_fails_closed)
{
    // A non-native collateral with NO staged policy entry -> GetCollateralPolicy miss -> fail closed.
    Terms t; t.collateral = U256(0x77);
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90); // scalar resolved, but no collateral policy
    const CovenantInputAsset in{t.collateral, t.vault_im};
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), CTransaction(CMutableTransaction{}), in, &snap),
                      SCRIPT_ERR_SCALARCFD_COLLATERAL);
}

BOOST_AUTO_TEST_CASE(asset_collateral_gate_rejections)
{
    // The gate (step 4) fails before input/output binding; build a fully-valid settling tx + input
    // and vary ONLY the staged policy, so the COLLATERAL error is attributable to the gate alone.
    Terms t; t.collateral = U256(0x77);
    const CovenantInputAsset in{t.collateral, t.vault_im};
    const auto build = [&](const ScalarCollateralPolicy& pol) {
        ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
        snap.AddCollateralPolicy(t.collateral, pol);
        const auto p = Expect(t, 90);
        return RunAsset(BuildScript(t), CTransaction(TxForAsset(p, t.owner, t.cp, t.collateral)), in, &snap);
    };
    // no COLLATERAL_SAFE bit / kyc / tfr / WRAP_REQUIRED all fail closed with SCALARCFD_COLLATERAL.
    BOOST_CHECK_EQUAL(build(ScalarCollateralPolicy{/*safe=*/false, 0, 0, 0}), SCRIPT_ERR_SCALARCFD_COLLATERAL);
    BOOST_CHECK_EQUAL(build(ScalarCollateralPolicy{true, /*kyc=*/1, 0, 0}),   SCRIPT_ERR_SCALARCFD_COLLATERAL);
    BOOST_CHECK_EQUAL(build(ScalarCollateralPolicy{true, 0, /*tfr=*/1, 0}),   SCRIPT_ERR_SCALARCFD_COLLATERAL);
    BOOST_CHECK_EQUAL(build(ScalarCollateralPolicy{true, 0, 0, /*WRAP=*/0x0001u}), SCRIPT_ERR_SCALARCFD_COLLATERAL);
}

BOOST_AUTO_TEST_CASE(asset_collateral_leg_above_int64_max)
{
    // An asset payout leg may exceed INT64_MAX (asset amounts are uint64). Full liquidation sends
    // ALL of a > INT64_MAX vault_im to cp; the uint64 output matcher must bind it without a CAmount
    // round-trip (which would wrap negative and fail). Pins the Slice-4c uint64 leg fix.
    Terms t; t.collateral = U256(0x77);
    t.vault_im = 0xC000000000000000ULL;   // ~1.38e19 > INT64_MAX (0x7FFF...)
    t.lambda_q = Q16(10);                 // X=90 -> f_loss 1.0 -> cp = vault_im, no owner leg
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    snap.AddCollateralPolicy(t.collateral, CleanPolicy());
    const auto p = Expect(t, 90);
    BOOST_CHECK_EQUAL(p.payout_cp, t.vault_im);                 // full liquidation
    BOOST_CHECK(p.payout_cp > 0x7FFFFFFFFFFFFFFFULL);           // genuinely above INT64_MAX
    const CovenantInputAsset in{t.collateral, t.vault_im};
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), CTransaction(TxForAsset(p, t.owner, t.cp, t.collateral)), in, &snap),
                      SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(asset_collateral_input_binding)
{
    Terms t; t.collateral = U256(0x77);
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    snap.AddCollateralPolicy(t.collateral, CleanPolicy());
    const auto p = Expect(t, 90);
    const auto mtx = CTransaction(TxForAsset(p, t.owner, t.cp, t.collateral));

    // No input asset (native coin) under an asset contract -> AMOUNT.
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), mtx, std::nullopt, &snap), SCRIPT_ERR_SCALARCFD_AMOUNT);
    // Wrong asset id -> AMOUNT.
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), mtx, CovenantInputAsset{U256(0x99), t.vault_im}, &snap),
                      SCRIPT_ERR_SCALARCFD_AMOUNT);
    // Wrong asset amount -> AMOUNT.
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), mtx, CovenantInputAsset{t.collateral, t.vault_im + 1}, &snap),
                      SCRIPT_ERR_SCALARCFD_AMOUNT);
}

BOOST_AUTO_TEST_CASE(asset_collateral_output_binding)
{
    Terms t; t.collateral = U256(0x77);
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    snap.AddCollateralPolicy(t.collateral, CleanPolicy());
    const auto p = Expect(t, 90);
    const CovenantInputAsset in{t.collateral, t.vault_im};

    // Native outputs (no AssetTLV) under an asset contract -> OUTPUTS.
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), in, &snap),
                      SCRIPT_ERR_SCALARCFD_OUTPUTS);
    // Wrong collateral asset id on the outputs -> OUTPUTS.
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t), CTransaction(TxForAsset(p, t.owner, t.cp, U256(0x99))), in, &snap),
                      SCRIPT_ERR_SCALARCFD_OUTPUTS);
    // nValue below the asset dust floor -> OUTPUTS.
    BOOST_CHECK_EQUAL(RunAsset(BuildScript(t),
                      CTransaction(TxForAsset(p, t.owner, t.cp, t.collateral, /*dust=*/static_cast<CAmount>(MIN) - 1)),
                      in, &snap), SCRIPT_ERR_SCALARCFD_OUTPUTS);
}

// ---- Encoding / context guards --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bad_source_type_enum_is_encoding_error)
{
    Terms t; t.source_type = 0x02;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(bad_operand_length_is_encoding_error)
{
    // strike pushed as 31 bytes instead of 32: the eval's exact-width check rejects it.
    Terms t;
    CScript s;
    s << valtype{0x01} << valtype{t.source_type} << ToVec(t.underlying) << LE32(t.feed_id) << LE64(t.fixing_ref)
      << LE32(t.deadline) << valtype{t.payoff_mode} << LE16(t.scalar_format)
      << Bytes(31, 0x33)                 // <-- malformed strike
      << ToVec(t.fallback) << LE32(t.lambda_q) << valtype{t.loss_dir} << ToVec(t.collateral)
      << LE64(t.vault_im) << t.owner << t.cp << OP_SCALAR_CFD_SETTLE;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(s, CTransaction(CMutableTransaction{}), t.vault_im, &snap), SCRIPT_ERR_SCALARCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(wrong_witness_version_is_context_error)
{
    Terms t;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap, ACTIVE_FLAGS,
                          /*witver=*/0), SCRIPT_ERR_SCALARCFD_CONTEXT);
}

BOOST_AUTO_TEST_CASE(bad_payoff_mode_is_encoding_error)
{
    Terms t; t.payoff_mode = 0x02; // mode 2 (deferred) -> not template-valid
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(bad_loss_direction_is_encoding_error)
{
    Terms t; t.loss_dir = 0x02;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(unknown_scalar_format_is_encoding_error)
{
    Terms t; t.scalar_format = 0x0099; // not SCALAR_FORMAT_RAW_U256_LE -> DecodeScalarValue fails
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(chain_intrinsic_nonzero_underlying_is_encoding_error)
{
    // The eval mirrors the parser invariant: CHAIN_INTRINSIC must commit a zero underlying.
    Terms t; t.source_type = 0x01; t.underlying = U256(0x22); // non-zero
    ScalarFixingSnapshot snap; // no entry needed; guard fires before the snapshot lookup
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_ENCODING);
}

// ---- Invalid terms (ComputeScalarCfdPayout rejects) -----------------------------------------

BOOST_AUTO_TEST_CASE(zero_lambda_is_terms_error)
{
    Terms t; t.lambda_q = 0;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_TERMS);
}

BOOST_AUTO_TEST_CASE(vault_below_min_is_terms_error)
{
    Terms t; t.vault_im = MIN - 1; // below the dust floor
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap),
                      SCRIPT_ERR_SCALARCFD_TERMS);
}

// ---- Output binding discipline --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(asset_tagged_output_rejected)
{
    Terms t; // partial: X=90 -> owner=900000, cp=100000
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    const auto p = Expect(t, 90);
    CMutableTransaction mtx = TxFor(p, t.owner, t.cp);
    // Tag the cp output with an asset TLV: the native covenant must NOT accept it.
    for (auto& o : mtx.vout) {
        if (o.scriptPubKey == P2TR(t.cp)) o.vExt = AssetTag(U256(0x77), /*amount=*/123);
    }
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(mtx), t.vault_im, &snap), SCRIPT_ERR_SCALARCFD_OUTPUTS);
}

BOOST_AUTO_TEST_CASE(distinct_outputs_required_for_shared_key)
{
    // owner and cp share a key with an equal split (cp == owner == 500000): two DISTINCT outputs
    // are required; a single output binds only one leg, so the other fails.
    Terms t; t.strike = A256(100); t.owner = Bytes(32, 0x5A); t.cp = Bytes(32, 0x5A);
    ScalarFixingSnapshot snap; AddEntry(snap, t, /*X=*/50);
    const auto p = Expect(t, 50);
    BOOST_REQUIRE_EQUAL(p.payout_owner, p.payout_cp); // 500000 each

    // Two distinct outputs -> passes.
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(TxFor(p, t.owner, t.cp)), t.vault_im, &snap), SCRIPT_ERR_OK);

    // Single output carrying one leg's amount -> the second leg has no distinct output to bind.
    CMutableTransaction one;
    one.vin.emplace_back();
    one.vout.emplace_back(static_cast<CAmount>(p.payout_owner), P2TR(t.owner));
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(one), t.vault_im, &snap), SCRIPT_ERR_SCALARCFD_OUTPUTS);
}

// ---- Pre-activation behaviour (the repurposed OP_NOP10) --------------------------------------

BOOST_AUTO_TEST_CASE(pre_activation_is_discouraged_nop)
{
    Terms t;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    // Flag off + DISCOURAGE set: behaves as the upgradable NOP it repurposes.
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap,
                          SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS),
                      SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(pre_activation_plain_nop_succeeds)
{
    Terms t;
    ScalarFixingSnapshot snap; AddEntry(snap, t, 90);
    // Flag off, no DISCOURAGE: a no-op; the leaf's operands remain and the top one is truthy.
    BOOST_CHECK_EQUAL(Run(BuildScript(t), CTransaction(CMutableTransaction{}), t.vault_im, &snap,
                          SCRIPT_VERIFY_TAPROOT),
                      SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
