// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/option_series.h>

#include <addresstype.h>
#include <arith_uint256.h>
#include <assets/asset.h>           // ParseIssuerReg, ComputeCorePolicyCommit (shared-builder regression)
#include <wallet/asset_registration.h>
#include <consensus/difficulty_cfd.h>
#include <key.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>
#include <wallet/contract.h> // BuildAssetTagTlv (test assertions)

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace wallet;

namespace {

// Fixed example inputs — OPTION_SERIES_FREEZE.md §7.1 (self-issuance, D1-b). series_salt is the
// frozen value SHA256("OPTION_SERIES_FREEZE example v1") embedded here so the test needs no setup.
OptionSeriesTerms FreezeExampleTerms()
{
    OptionSeriesTerms t;
    t.descriptor_version = kOptionDescriptorVersion;          // 1
    t.issuance_mode      = OPTION_ISSUANCE_SELF;              // 0
    t.leaf_set           = OPTION_LEAFSET_SETTLE_BUYBACK;     // 1 (D1-b)
    const auto wk = ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    t.writer_key = XOnlyPubKey{wk};
    t.strike_nbits           = 0x1d00ffff;
    t.fixing_height          = 150000;
    t.settle_lock_height     = 150100;
    t.lambda_q               = 218453;
    t.lot_im_sats            = 3'000'000'000;   // 30 TSC; K=3000, N=100
    t.lot_count              = 100;
    t.reference_premium_sats = 50'000'000'000;  // 500 TSC, display only
    const auto sb = ParseHex("1d59c4b99e941c31d184cf90f76bde031aa142ce855c37b9cd887004baf86f52");
    std::copy(sb.begin(), sb.end(), t.series_salt.begin());
    return t;
}

// --- Settlement consensus-eval harness (mirrors difficulty_contract_tests.cpp) ---

class MockFixingContext final : public FixingContext
{
public:
    std::map<int, uint32_t> nbits_by_height;
    int context_height{0};
    int maturity{0};
    uint256 pow_limit{ArithToUint256(~arith_uint256{0})};

    std::optional<uint32_t> NBitsAt(int height) const override
    {
        if (!DiffCfdFixingResolvable(height, context_height, maturity)) return std::nullopt;
        auto it = nbits_by_height.find(height);
        if (it == nbits_by_height.end()) return std::nullopt;
        return it->second;
    }
    int ContextHeight() const override { return context_height; }
    std::optional<arith_uint256> DecodeTarget(uint32_t nBits) const override { return DeriveTarget(nBits, pow_limit); }
};

CKey TestCKey(unsigned char seed)
{
    std::vector<unsigned char> sk(32, 0);
    sk[31] = seed; // small non-zero scalar -> valid private key
    CKey k;
    k.Set(sk.begin(), sk.end(), /*fCompressedIn=*/true);
    BOOST_REQUIRE(k.IsValid());
    return k;
}
XOnlyPubKey TestKey(unsigned char seed) { return XOnlyPubKey(TestCKey(seed).GetPubKey()); }

uint32_t CanonicalNBits(uint64_t target) { arith_uint256 t{target}; return t.GetCompact(); }

// A valid OPTION series for settlement: writer = short leg, 10 TSC IM, lambda 10, strike difficulty
// 1e6, fixing 50, settle lock at fixing + maturity. D1-b (settle + buy-back).
OptionSeriesTerms MakeSettlementSeriesTerms()
{
    OptionSeriesTerms t;
    t.descriptor_version = kOptionDescriptorVersion;
    t.issuance_mode = OPTION_ISSUANCE_SELF;
    t.leaf_set = OPTION_LEAFSET_SETTLE_BUYBACK;
    t.writer_key = TestKey(0x11);
    t.strike_nbits = CanonicalNBits(1'000'000);
    t.fixing_height = 50;
    t.settle_lock_height = 50 + DIFFCFD_MATURITY_DEPTH;
    t.lambda_q = 10u * (1u << 16);
    t.lot_im_sats = 1'000'000'000; // 10 TSC
    t.lot_count = 4;
    t.reference_premium_sats = 0;  // display only; lot terms use the pinned MIN_SETTLE_OUTPUT
    t.series_salt = uint256::ONE;
    return t;
}

// FundedOutput from a distinct outpoint (vout on a fixed txid) + the CTxOut it spends.
FundedOutput Funded(uint32_t vout, CAmount value, const CScript& spk, const std::vector<unsigned char>& vext = {})
{
    CTxOut o(value, spk);
    o.vExt = vext;
    return FundedOutput{COutPoint(Txid::FromUint256(uint256::ONE), vout), o};
}
// Funded vault for lot `i` (derived spk + the exact per-lot IM value, native-only).
FundedOutput VaultFunded(const OptionSeriesTerms& terms, const uint256& sid, uint32_t i, uint32_t vout = 0)
{
    const OptionLot lot = DeriveOptionLot(terms, sid, i);
    return Funded(vout, lot.record.terms.short_leg.im, lot.vault_spk);
}
// Funded asset-tagged token input (dust native + AssetTag(sid, units)).
FundedOutput TokenFunded(uint32_t vout, const uint256& sid, uint64_t units, const CScript& spk)
{
    return Funded(vout, 546, spk, BuildAssetTagTlv(sid, units));
}
// Funded native-only fee input.
FundedOutput NativeFunded(uint32_t vout, CAmount value, const CScript& spk = CScript())
{
    return Funded(vout, value, spk);
}

// Build the settlement via the production helper, assemble the tx, and run it through the real
// interpreter against `verify_spk` with a mock FixingContext. SCRIPT_ERR_OK on a clean settlement.
ScriptError RunOptionVaultSettlement(const OptionSeriesTerms& terms, const uint256& sid, uint32_t lot_index,
                                     const CScript& verify_spk, uint32_t realized_nbits, const uint256& pow_limit,
                                     int maturity, int context_height)
{
    const OptionLot lot = DeriveOptionLot(terms, sid, lot_index);
    const CAmount im = lot.record.terms.short_leg.im;
    DifficultySettlementSkeleton skel;
    std::string err;
    if (!BuildOptionSettlementSkeleton(terms, lot_index, VaultFunded(terms, sid, lot_index), realized_nbits,
                                       pow_limit, skel, err)) {
        return SCRIPT_ERR_UNKNOWN_ERROR;
    }

    CMutableTransaction mtx;
    mtx.vin.push_back(skel.vault_input);
    mtx.nLockTime = skel.nlocktime;
    for (const auto& o : skel.payouts) mtx.vout.push_back(o);
    const CTransaction tx{mtx};

    MockFixingContext fixing;
    fixing.context_height = context_height;
    fixing.maturity = maturity;
    fixing.pow_limit = pow_limit;
    fixing.nbits_by_height[lot.record.terms.fixing_height] = realized_nbits;

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
                               SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    TransactionSignatureChecker checker(&tx, 0, im, MissingDataBehavior::FAIL, &fixing);
    ScriptError serror = SCRIPT_ERR_OK;
    const bool ok = VerifyScript(CScript(), verify_spk, &tx.vin[0].scriptWitness, flags, checker, &serror);
    return ok ? SCRIPT_ERR_OK : serror;
}

// Run ONE pot input through the interpreter against the pot scriptPubKey. OUTPUTMATCH_ASSET inspects
// the tx outputs, so the verdict depends on whether `tx` carries the matching 1-unit-to-sink output.
ScriptError RunPotSpend(const CScript& pot_spk, const CTransaction& tx, unsigned int input_index, CAmount pot_value)
{
    MockFixingContext fixing; // unused by OUTPUTMATCH_ASSET, but the checker ctor takes one
    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT;
    TransactionSignatureChecker checker(&tx, input_index, pot_value, MissingDataBehavior::FAIL, &fixing);
    ScriptError serror = SCRIPT_ERR_OK;
    const bool ok = VerifyScript(CScript(), pot_spk, &tx.vin[input_index].scriptWitness, flags, checker, &serror);
    return ok ? SCRIPT_ERR_OK : serror;
}

// Fill the script-path signature slot of input `in_index` (witness [sig, leaf, control]) with a
// BIP341 SIGHASH_DEFAULT (output-binding) Schnorr sig over the buy-back leaf, signed by the writer.
// `spent` are the prevout CTxOuts of every input, in vin order (the taproot sighash commits to all).
void SignBuybackInput(CMutableTransaction& mtx, unsigned int in_index, const std::vector<CTxOut>& spent,
                      const CScript& leaf, const CKey& key)
{
    const CTransaction tx{mtx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);

    ScriptExecutionData execdata;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash =
        ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, std::span<const unsigned char>(leaf.data(), leaf.size()));
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFu;

    uint256 sighash;
    BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, tx, in_index, SIGHASH_DEFAULT,
                                       SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));
    std::vector<unsigned char> sig(64);
    BOOST_REQUIRE(key.SignSchnorr(sighash, sig, /*merkle_root=*/nullptr, uint256::ZERO));
    mtx.vin[in_index].scriptWitness.stack[0] = sig;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(option_series_tests, BasicTestingSetup)

// §7.2 — AUTHORITATIVE conformance vectors (pure SHA256 + secp256k1 x-only validity). These pin the
// highest-churn identity bytes; any drift in freeze §2/§3/§4.1/§4.2 fails here.
BOOST_AUTO_TEST_CASE(freeze_vectors_authoritative)
{
    const OptionSeriesTerms t = FreezeExampleTerms();

    const std::vector<unsigned char> descriptor = SerializeOptionDescriptor(t);
    BOOST_CHECK_EQUAL(descriptor.size(), 103U);
    BOOST_CHECK_EQUAL(HexStr(descriptor),
        "01000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "ffff001df0490200544a020055550300005ed0b2000000006400000000743ba40b000000"
        "1d59c4b99e941c31d184cf90f76bde031aa142ce855c37b9cd887004baf86f52");

    const uint256 asset_id = ComputeOptionSeriesId(t);
    BOOST_CHECK_EQUAL(HexStr(asset_id),
        "c4ed91972ef3014baa1faccc37b7ec80f43cdd4cccf258ec25215371ccd5e96e");

    BOOST_CHECK_EQUAL(HexStr(DeriveOptionLotSalt(asset_id, 0)),
        "14ab1739cea05cf202f22d1fc22dd7456be27cb24966419a4e102507f5e6c9ee");
    BOOST_CHECK_EQUAL(HexStr(DeriveOptionLotSalt(asset_id, 1)),
        "bb81c9b301ba11646171086ec9ffe45865248357d1d6368c96883a245d2a1351");
    BOOST_CHECK_EQUAL(HexStr(DeriveOptionLotSalt(asset_id, 99)),
        "da643369b580f9d917b0226a689f3288ad733cdbcbed1b4f4faafc5d2f06b650");

    struct SinkVec { uint32_t i; uint32_t ctr; const char* key; };
    const SinkVec sinks[] = {
        {0,  2, "161414ef412ed20bdea13af770a92ae8efdacf55dfbdeed4fb691f4aa525a82c"},
        {1,  0, "c5c044a4284751ce4d8ad7f925ac222cedd3036fb62925c0a138ce12c8f0ac4d"},
        {99, 0, "010072e463e0158c2db1814057b929bd14babf9d767afeee4e61b72bd20ba19e"},
    };
    for (const auto& v : sinks) {
        const auto [sink_key, ctr] = DeriveOptionSink(asset_id, v.i);
        BOOST_CHECK_EQUAL(ctr, v.ctr);
        BOOST_CHECK_EQUAL(HexStr(sink_key), v.key);
        const CScript sink_spk = GetScriptForDestination(WitnessV1Taproot{sink_key});
        BOOST_CHECK_EQUAL(HexStr(sink_spk), std::string("5120") + v.key);
    }
}

// §7.3 — emit the reference-impl chain (contract_id / pot_key / vault_key / leaves). These come from
// the REAL ComputeDifficultyContractId / BuildDifficultyLeafScript + consensus taproot, so this test
// is the authoritative source to paste back into OPTION_SERIES_FREEZE.md §7.3.
BOOST_AUTO_TEST_CASE(freeze_vectors_reference_impl)
{
    const OptionSeriesTerms t = FreezeExampleTerms();
    const uint256 asset_id = ComputeOptionSeriesId(t);

    for (uint32_t i : {0u, 1u, 99u}) {
        const OptionLot lot = DeriveOptionLot(t, asset_id, i);

        // Keystone invariant: the lot's counterparty payout key IS the pot output key.
        BOOST_CHECK(lot.record.terms.short_leg.cp_key == lot.pot_key);
        // Sanity: a real, finalized vault address.
        BOOST_CHECK(lot.vault_key.IsFullyValid());
        BOOST_CHECK(!lot.buyback_leaf.empty()); // D1-b

        BOOST_TEST_MESSAGE("lot " << i
            << "\n  salt        = " << HexStr(lot.salt)
            << "\n  contract_id = " << HexStr(lot.contract_id)
            << "\n  pot_key     = " << HexStr(lot.pot_key)
            << "\n  pot_spk     = " << HexStr(lot.pot_spk)
            << "\n  vault_key   = " << HexStr(lot.vault_key)
            << "\n  vault_spk   = " << HexStr(lot.vault_spk)
            << "\n  settle_leaf = " << HexStr(lot.settle_leaf)
            << "\n  buyback_leaf= " << HexStr(lot.buyback_leaf));
    }

    // Distinct per-lot vault addresses (per-lot salt -> distinct contract_id -> distinct taptweak).
    const OptionLot l0 = DeriveOptionLot(t, asset_id, 0);
    const OptionLot l1 = DeriveOptionLot(t, asset_id, 1);
    BOOST_CHECK(l0.vault_key != l1.vault_key);
    BOOST_CHECK(l0.pot_key != l1.pot_key);
}

// Slice 2 #1 — a tokenized lot settles through the REAL interpreter: proves the D1-b (settle+buyback)
// vault leaf is byte-compatible with OP_DIFFCFD_SETTLE, the contract_id commitment + CLTV hold, and
// the control block reconstructed from the two-leaf tree validates against the on-chain output key.
BOOST_AUTO_TEST_CASE(option_vault_settles_through_consensus)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0);
    const uint256 wide = ArithToUint256(~arith_uint256{0});
    // Partial split: realized target below strike => difficulty rose => writer partly liquidated to pot.
    const ScriptError res = RunOptionVaultSettlement(t, sid, 0, lot.vault_spk, CanonicalNBits(950'000), wide,
                                                     /*maturity=*/0, /*context_height=*/lot.record.terms.fixing_height + 1);
    BOOST_CHECK_MESSAGE(res == SCRIPT_ERR_OK, "option settlement failed: " << ScriptErrorString(res));
}

// The covenant split: partial (writer + pot), full pot (deep ITM), full writer (OTM); plus the
// out-of-range powLimit rejection. Outputs are conserved (sum == im) and a zero leg is skipped.
BOOST_AUTO_TEST_CASE(option_settlement_skeleton_shapes)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0);
    const uint256 wide = ArithToUint256(~arith_uint256{0});
    const CAmount im = lot.record.terms.short_leg.im;
    const std::vector<unsigned char> settle_leaf_bytes(lot.settle_leaf.begin(), lot.settle_leaf.end());
    const CScript writer_spk = GetScriptForDestination(WitnessV1Taproot{lot.record.terms.short_leg.owner_key});

    auto build = [&](uint32_t realized, DifficultySettlementSkeleton& skel) {
        std::string err;
        return BuildOptionSettlementSkeleton(t, 0, VaultFunded(t, sid, 0), realized, wide, skel, err);
    };

    // Partial -> two outputs (writer owner + pot cp), output-conserved, keeper-shaped.
    DifficultySettlementSkeleton partial;
    BOOST_REQUIRE(build(CanonicalNBits(950'000), partial));
    BOOST_REQUIRE_EQUAL(partial.payouts.size(), 2u);
    BOOST_CHECK(partial.payout.payout_owner > 0 && partial.payout.payout_cp > 0);
    BOOST_CHECK_EQUAL(partial.payouts[0].nValue + partial.payouts[1].nValue, im);
    BOOST_CHECK_EQUAL(partial.nlocktime, lot.record.terms.settle_lock_height);
    BOOST_CHECK(partial.vault_input.nSequence != CTxIn::SEQUENCE_FINAL);
    BOOST_REQUIRE_EQUAL(partial.vault_input.scriptWitness.stack.size(), 2u); // [leaf, control], no signature
    BOOST_CHECK(partial.vault_input.scriptWitness.stack[0] == settle_leaf_bytes);
    BOOST_CHECK(partial.payouts[0].scriptPubKey == writer_spk);
    BOOST_CHECK(partial.payouts[1].scriptPubKey == lot.pot_spk);

    // Deep adverse -> full liquidation to the pot: single cp output == im, owner skipped.
    DifficultySettlementSkeleton liq;
    BOOST_REQUIRE(build(CanonicalNBits(800'000), liq));
    BOOST_REQUIRE_EQUAL(liq.payouts.size(), 1u);
    BOOST_CHECK_EQUAL(liq.payout.payout_owner, 0u);
    BOOST_CHECK_EQUAL(liq.payouts[0].nValue, im);
    BOOST_CHECK(liq.payouts[0].scriptPubKey == lot.pot_spk);

    // OTM (difficulty fell) -> writer keeps all: single owner output == im, pot skipped.
    DifficultySettlementSkeleton otm;
    BOOST_REQUIRE(build(CanonicalNBits(1'100'000), otm));
    BOOST_REQUIRE_EQUAL(otm.payouts.size(), 1u);
    BOOST_CHECK_EQUAL(otm.payout.payout_cp, 0u);
    BOOST_CHECK_EQUAL(otm.payouts[0].nValue, im);
    BOOST_CHECK(otm.payouts[0].scriptPubKey == writer_spk);

    // Out-of-range strike for a tiny powLimit -> rejected (mirrors the consensus range check).
    DifficultySettlementSkeleton bad;
    std::string err;
    const uint256 tiny = ArithToUint256(arith_uint256{100});
    BOOST_CHECK(!BuildOptionSettlementSkeleton(t, 0, VaultFunded(t, sid, 0), CanonicalNBits(950'000), tiny, bad, err));

    // A funded UTXO that is NOT the derived vault is rejected (trust boundary): wrong spk, wrong value.
    DifficultySettlementSkeleton mism;
    FundedOutput wrong_spk = VaultFunded(t, sid, 0);
    wrong_spk.txout.scriptPubKey = GetScriptForDestination(WitnessV1Taproot{TestKey(0x77)});
    BOOST_CHECK(!BuildOptionSettlementSkeleton(t, 0, wrong_spk, CanonicalNBits(950'000), wide, mism, err));
    FundedOutput wrong_val = VaultFunded(t, sid, 0);
    wrong_val.txout.nValue += 1; // vault value mismatch (finding #6)
    BOOST_CHECK(!BuildOptionSettlementSkeleton(t, 0, wrong_val, CanonicalNBits(950'000), wide, mism, err));
}

// The control block is tree-specific: a D1-b (settle+buyback) settlement witness must NOT validate
// against the settle-ONLY (D1-a) vault output key — different merkle root => different taptweak.
BOOST_AUTO_TEST_CASE(option_settlement_wrong_tree_rejected)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0); // D1-b
    const uint256 wide = ArithToUint256(~arith_uint256{0});
    const CScript settle_only_spk =
        GetScriptForDestination(CreateOptionVaultBuilder(lot.settle_leaf, /*buyback_leaf=*/CScript()).GetOutput());
    BOOST_CHECK(settle_only_spk != lot.vault_spk);
    const ScriptError res = RunOptionVaultSettlement(t, sid, 0, settle_only_spk, CanonicalNBits(950'000), wide,
                                                     /*maturity=*/0, /*context_height=*/lot.record.terms.fixing_height + 1);
    BOOST_CHECK(res != SCRIPT_ERR_OK);
}

// Slice 2 #2 — a holder redeems a pot: the builder's tx retires exactly 1 unit to the pot's sink,
// returns token change + the native sweep, and the pot leaf validates through the real interpreter.
BOOST_AUTO_TEST_CASE(option_pot_redeems_to_sink)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0);
    const CScript holder = GetScriptForDestination(WitnessV1Taproot{TestKey(0x33)});

    const OptionRedemptionPot pot{0, Funded(0, 100'000, lot.pot_spk)};
    CMutableTransaction mtx;
    std::string err;
    BOOST_REQUIRE(BuildOptionRedemption(t, {pot},
        /*token_inputs=*/{TokenFunded(1, sid, 3, holder)},
        /*native_inputs=*/{NativeFunded(2, 5'000)},
        holder, /*fee=*/1'000, /*dust=*/546, mtx, err));

    // Outputs: 1 sink (1 unit) + token change (m-k = 2 units) + native sweep.
    BOOST_REQUIRE_EQUAL(mtx.vout.size(), 3u);
    BOOST_CHECK(mtx.vout[0].scriptPubKey == lot.sink_spk);
    BOOST_CHECK(mtx.vout[0].vExt == BuildAssetTagTlv(sid, 1));
    BOOST_CHECK(mtx.vout[1].vExt == BuildAssetTagTlv(sid, 2));
    BOOST_CHECK(mtx.vout[2].vExt.empty()); // native sweep
    // Inputs: pot (covenant witness, no signature) + token + native.
    BOOST_REQUIRE_EQUAL(mtx.vin.size(), 3u);
    BOOST_REQUIRE_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 2u);

    const CTransaction tx{mtx};
    BOOST_CHECK_EQUAL(RunPotSpend(lot.pot_spk, tx, 0, pot.pot.txout.nValue), SCRIPT_ERR_OK);
}

// The pot leaf demands EXACTLY one unit at EXACTLY its sink: no sink, wrong sink, wrong asset, and
// amount 2 all fail (OUTPUTMATCH_ASSET is an exact-amount match).
BOOST_AUTO_TEST_CASE(option_pot_requires_exact_unit_to_sink)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0);
    const CScript holder = GetScriptForDestination(WitnessV1Taproot{TestKey(0x33)});
    const OptionRedemptionPot pot{0, Funded(0, 100'000, lot.pot_spk)};

    CMutableTransaction base;
    std::string err;
    BOOST_REQUIRE(BuildOptionRedemption(t, {pot}, {TokenFunded(1, sid, 1, holder)},
        {NativeFunded(2, 5'000)}, holder, 1'000, 546, base, err));

    // Baseline (units == k -> no change; outputs: sink + native sweep) passes.
    BOOST_CHECK_EQUAL(RunPotSpend(lot.pot_spk, CTransaction{base}, 0, pot.pot.txout.nValue), SCRIPT_ERR_OK);

    auto mutate = [&](auto fn) { CMutableTransaction m = base; fn(m); return RunPotSpend(lot.pot_spk, CTransaction{m}, 0, pot.pot.txout.nValue); };
    BOOST_CHECK(mutate([](CMutableTransaction& m){ m.vout.erase(m.vout.begin()); }) != SCRIPT_ERR_OK);                          // no sink
    BOOST_CHECK(mutate([&](CMutableTransaction& m){ m.vout[0].scriptPubKey = GetScriptForDestination(WitnessV1Taproot{TestKey(0x44)}); }) != SCRIPT_ERR_OK); // wrong sink
    BOOST_CHECK(mutate([&](CMutableTransaction& m){ m.vout[0].vExt = BuildAssetTagTlv(uint256::ONE, 1); }) != SCRIPT_ERR_OK);   // wrong asset
    BOOST_CHECK(mutate([&](CMutableTransaction& m){ m.vout[0].vExt = BuildAssetTagTlv(sid, 2); }) != SCRIPT_ERR_OK);            // amount 2
}

// Unique sinks make redemption one-token-one-pot: with both sinks present both pots spend; remove
// one sink and only its pot fails (the other still finds its own).
BOOST_AUTO_TEST_CASE(option_cross_lot_unique_sinks)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot l0 = DeriveOptionLot(t, sid, 0);
    const OptionLot l1 = DeriveOptionLot(t, sid, 1);
    const CScript holder = GetScriptForDestination(WitnessV1Taproot{TestKey(0x33)});

    const OptionRedemptionPot p0{0, Funded(0, 100'000, l0.pot_spk)};
    const OptionRedemptionPot p1{1, Funded(1, 100'000, l1.pot_spk)};

    CMutableTransaction mtx;
    std::string err;
    BOOST_REQUIRE(BuildOptionRedemption(t, {p0, p1}, {TokenFunded(2, sid, 2, holder)},
        {NativeFunded(3, 5'000)}, holder, 1'000, 546, mtx, err));
    BOOST_REQUIRE_EQUAL(mtx.vout.size(), 3u); // sink0 + sink1 + native sweep (units == k -> no change)

    const CTransaction tx{mtx};
    BOOST_CHECK_EQUAL(RunPotSpend(l0.pot_spk, tx, 0, p0.pot.txout.nValue), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(RunPotSpend(l1.pot_spk, tx, 1, p1.pot.txout.nValue), SCRIPT_ERR_OK);

    // Drop sink_1: pot_0 still finds sink_0, pot_1 cannot find its sink.
    CMutableTransaction m = mtx;
    m.vout.erase(m.vout.begin() + 1);
    const CTransaction tx2{m};
    BOOST_CHECK_EQUAL(RunPotSpend(l0.pot_spk, tx2, 0, p0.pot.txout.nValue), SCRIPT_ERR_OK);
    BOOST_CHECK(RunPotSpend(l1.pot_spk, tx2, 1, p1.pot.txout.nValue) != SCRIPT_ERR_OK);
}

// Slice 2 #3 — the writer's early-unwind: spending a lot vault via the buy-back leaf needs BOTH the
// writer's (output-binding) signature AND a 1-unit retire to the lot's sink. With both, it settles;
// drop the sink (re-signing so the failure is the OUTPUTMATCH, not the sig) and it fails.
BOOST_AUTO_TEST_CASE(option_buyback_writer_reclaims_with_sig_and_sink)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms(); // writer = TestKey(0x11), D1-b
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0);
    const CKey writer = TestCKey(0x11);
    const CAmount vault_value = lot.record.terms.short_leg.im;
    const CScript writer_spk = GetScriptForDestination(WitnessV1Taproot{lot.record.terms.short_leg.owner_key});

    // Construct the funded inputs once, reuse for the builder AND the sighash prevouts.
    const FundedOutput vault = VaultFunded(t, sid, 0); // vout 0
    const FundedOutput tok = TokenFunded(1, sid, 2, GetScriptForDestination(WitnessV1Taproot{TestKey(0x55)}));
    const FundedOutput nat = NativeFunded(2, 5'000, GetScriptForDestination(WitnessV1Taproot{TestKey(0x66)}));

    CMutableTransaction mtx;
    std::string err;
    BOOST_REQUIRE(BuildOptionBuyback(t, 0, vault, {tok}, {nat}, writer_spk, /*fee=*/1'000, /*dust=*/546, mtx, err));

    // Structure: vault (script-path witness placeholder) + token + native; sink + token change + sweep.
    BOOST_REQUIRE_EQUAL(mtx.vin.size(), 3u);
    BOOST_REQUIRE_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 3u); // [sig, leaf, control]
    BOOST_CHECK(mtx.vout[0].scriptPubKey == lot.sink_spk);
    BOOST_CHECK(mtx.vout[0].vExt == BuildAssetTagTlv(sid, 1));

    // Prevout CTxOuts in vin order for the taproot sighash (exactly the funded inputs).
    const std::vector<CTxOut> spent{vault.txout, tok.txout, nat.txout};

    auto verify = [&](const CMutableTransaction& m) {
        const CTransaction tx{m};
        MockFixingContext fixing;
        PrecomputedTransactionData td;
        td.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);
        const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT;
        TransactionSignatureChecker checker(&tx, 0, vault_value, td, MissingDataBehavior::FAIL, &fixing);
        ScriptError serr = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), lot.vault_spk, &tx.vin[0].scriptWitness, flags, checker, &serr);
        return ok ? SCRIPT_ERR_OK : serr;
    };

    // Signed, sink present -> the writer reclaims the vault.
    SignBuybackInput(mtx, 0, spent, lot.buyback_leaf, writer);
    const ScriptError signed_res = verify(mtx);
    BOOST_CHECK_MESSAGE(signed_res == SCRIPT_ERR_OK, "buy-back failed: " << ScriptErrorString(signed_res));

    // Valid signature but no sink output -> OUTPUTMATCH fails (re-sign so it isn't a sig mismatch).
    CMutableTransaction nosink = mtx;
    nosink.vout.erase(nosink.vout.begin()); // remove the sink
    SignBuybackInput(nosink, 0, spent, lot.buyback_leaf, writer);
    BOOST_CHECK(verify(nosink) != SCRIPT_ERR_OK);
}

// #7 — redemption input hardening: bad asset/native/dup/dust/cap inputs are all rejected by the
// builder (no longer the RPC's job alone). Each case is a single negative on an otherwise-valid call.
BOOST_AUTO_TEST_CASE(option_redemption_input_hardening)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const uint256 sid = ComputeOptionSeriesId(t);
    const OptionLot lot = DeriveOptionLot(t, sid, 0);
    const CScript holder = GetScriptForDestination(WitnessV1Taproot{TestKey(0x33)});
    const OptionRedemptionPot pot{0, Funded(0, 100'000, lot.pot_spk)};
    CMutableTransaction mtx;
    std::string err;

    // Baseline OK.
    BOOST_CHECK(BuildOptionRedemption(t, {pot}, {TokenFunded(1, sid, 1, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, 546, mtx, err));

    // (a) token input carrying a DIFFERENT asset -> rejected (finding #2).
    BOOST_CHECK(!BuildOptionRedemption(t, {pot}, {TokenFunded(1, uint256::ONE, 1, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, 546, mtx, err));
    // (b) token input that is native-only (no AssetTag) -> rejected.
    BOOST_CHECK(!BuildOptionRedemption(t, {pot}, {Funded(1, 546, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, 546, mtx, err));
    // (c) native fee input that is asset-tagged -> rejected (finding #3).
    BOOST_CHECK(!BuildOptionRedemption(t, {pot}, {TokenFunded(1, sid, 1, holder)}, {TokenFunded(2, sid, 1, holder)}, holder, 1'000, 546, mtx, err));
    // (d) pot UTXO that is asset-tagged -> rejected (pots are native-only).
    BOOST_CHECK(!BuildOptionRedemption(t, {{0, Funded(0, 100'000, lot.pot_spk, BuildAssetTagTlv(sid, 1))}},
                                       {TokenFunded(1, sid, 1, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, 546, mtx, err));
    // (e) dust below floor / huge dust -> rejected (finding #4).
    BOOST_CHECK(!BuildOptionRedemption(t, {pot}, {TokenFunded(1, sid, 1, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, /*dust=*/0, mtx, err));
    BOOST_CHECK(!BuildOptionRedemption(t, {pot}, {TokenFunded(1, sid, 2, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, /*dust=*/MAX_MONEY, mtx, err));
    // (f) duplicate input outpoint (pot and token share vout 0) -> rejected.
    BOOST_CHECK(!BuildOptionRedemption(t, {pot}, {TokenFunded(0, sid, 1, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, 546, mtx, err));

    // (g) 64 asset-output cap: 64 pots + token change => 65 AssetTag outputs -> rejected (finding #5).
    OptionSeriesTerms big = MakeSettlementSeriesTerms();
    big.lot_count = 70;
    const uint256 bsid = ComputeOptionSeriesId(big);
    std::vector<OptionRedemptionPot> many;
    for (uint32_t i = 0; i < 64; ++i) many.push_back({i, Funded(i, 100'000, DeriveOptionLot(big, bsid, i).pot_spk)});
    BOOST_CHECK(!BuildOptionRedemption(big, many, {TokenFunded(100, bsid, 100, holder)}, {NativeFunded(101, 100'000'000)}, holder, 1'000, 546, mtx, err));

    // (h) invalid OptionSeriesTerms (bad descriptor_version) is rejected by the builder itself.
    {
        OptionSeriesTerms bad_terms = MakeSettlementSeriesTerms();
        bad_terms.descriptor_version = 3;
        const uint256 bts = ComputeOptionSeriesId(bad_terms);
        const OptionRedemptionPot bp{0, Funded(0, 100'000, DeriveOptionLot(bad_terms, bts, 0).pot_spk)};
        BOOST_CHECK(!BuildOptionRedemption(bad_terms, {bp}, {TokenFunded(1, bts, 1, holder)}, {NativeFunded(2, 5'000)}, holder, 1'000, 546, mtx, err));
    }

    // (i) duplicate lot_index (two distinct UTXOs, same lot) -> rejected (would burn two units for one lot).
    {
        const OptionRedemptionPot d0{0, Funded(0, 100'000, lot.pot_spk)};
        const OptionRedemptionPot d1{0, Funded(1, 100'000, lot.pot_spk)};
        BOOST_CHECK(!BuildOptionRedemption(t, {d0, d1}, {TokenFunded(2, sid, 2, holder)}, {NativeFunded(3, 5'000)}, holder, 1'000, 546, mtx, err));
    }
}

// #4 — series-terms validation: a valid series passes; each bad field is rejected before serialization.
BOOST_AUTO_TEST_CASE(option_series_terms_validation)
{
    const uint256 wide = ArithToUint256(~arith_uint256{0});
    std::string err;
    BOOST_CHECK(ValidateOptionSeriesTerms(MakeSettlementSeriesTerms(), &wide, err));

    auto rejected = [&](auto fn) {
        OptionSeriesTerms t = MakeSettlementSeriesTerms();
        fn(t);
        std::string e;
        return !ValidateOptionSeriesTerms(t, &wide, e);
    };
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.descriptor_version = 3; }));     // 1 + 2 are the only supported versions
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.direction = 2; }));               // call(0)/put(1) only
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.direction = OPTION_DIRECTION_PUT; })); // put needs v2 (default fixture is v1)
    // v2 is valid for BOTH directions; a put round-trips through the descriptor and derives a DIFFERENT vault.
    {
        OptionSeriesTerms v2call = MakeSettlementSeriesTerms();
        v2call.descriptor_version = kOptionDescriptorVersionDirectional;
        std::string e;
        BOOST_CHECK(ValidateOptionSeriesTerms(v2call, &wide, e));
        OptionSeriesTerms put = v2call;
        put.direction = OPTION_DIRECTION_PUT;
        BOOST_CHECK(ValidateOptionSeriesTerms(put, &wide, e));
        // descriptor parse round-trip preserves direction; call vs put are distinct ids + vaults.
        const auto pd = ParseOptionSeriesDescriptor(SerializeOptionDescriptor(put));
        BOOST_REQUIRE(pd.has_value());
        BOOST_CHECK_EQUAL(pd->direction, OPTION_DIRECTION_PUT);
        const uint256 csid = ComputeOptionSeriesId(v2call), psid = ComputeOptionSeriesId(put);
        BOOST_CHECK(csid != psid);
        BOOST_CHECK(DeriveOptionLot(v2call, csid, 0).vault_spk != DeriveOptionLot(put, psid, 0).vault_spk);
    }
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.issuance_mode = 9; }));
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.leaf_set = 9; }));
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.writer_key = XOnlyPubKey{}; }));
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.lot_count = 0; }));
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.lot_im_sats = MIN_SETTLE_OUTPUT - 1; }));
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.reference_premium_sats = -1; }));
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.lambda_q = 0; }));                       // zero leverage
    BOOST_CHECK(rejected([](OptionSeriesTerms& t) { t.settle_lock_height = t.fixing_height; })); // CLTV before burial
}

// §6.6 regression — the EXTRACTED shared builder (wallet/asset_registration) must produce IssuerReg
// bytes the consensus parser accepts and reads back unchanged, for BOTH a root ticker and a one-hop
// child. This pins the shared builder == what registerasset / the parser expect, so a later migration
// of root registerasset onto this builder is provably byte-equivalent. Also exercises the hardened
// preconditions (ticker grammar, icu_visibility) on the BuildAssetRegistrationTLVs entry point.
BOOST_AUTO_TEST_CASE(shared_issuerreg_roundtrips_through_parser)
{
    auto check = [](const std::string& ticker) {
        uint256 asset_id; std::fill(asset_id.begin(), asset_id.end(), 0x07);
        uint256 vk_commit; std::fill(vk_commit.begin(), vk_commit.end(), 0xAB);
        uint256 ctxt; std::fill(ctxt.begin(), ctxt.end(), 0x11);
        uint256 plain; std::fill(plain.begin(), plain.end(), 0x22);
        std::array<unsigned char, 16> salt{}; salt.fill(0x44);
        const uint32_t policy_bits = assets::MINT_ALLOWED;
        const uint16_t allowed = assets::SPK_DEFAULT_ALLOWED;
        const uint256 core_commit = assets::ComputeCorePolicyCommit(allowed, policy_bits, /*kyc=*/0, /*tfr=*/0);

        const auto tlv = BuildIssuerRegV1(
            asset_id, policy_bits, allowed, ticker, /*decimals=*/0, /*unlock_fees=*/500000000u,
            /*kyc_flags=*/0, vk_commit, /*max_root_age=*/0, /*tfr_flags=*/0, /*compliance_root_commit=*/uint256(),
            /*icu_flags=*/0, /*issuance_cap_units=*/100, ctxt, plain, salt,
            /*icu_version=*/1, /*icu_visibility=*/0, core_commit, /*policy_epoch=*/0, /*policy_quorum_bps=*/0);

        const auto reg = assets::ParseIssuerReg(tlv);
        BOOST_REQUIRE_MESSAGE(reg.has_value(), "ParseIssuerReg rejected the shared-builder IssuerReg for ticker " << ticker);
        BOOST_CHECK(reg->asset_id == asset_id);
        BOOST_CHECK_EQUAL(reg->policy_bits, policy_bits);
        BOOST_CHECK_EQUAL(reg->allowed_spk_families, allowed);
        BOOST_CHECK_EQUAL(reg->ticker, ticker);
        BOOST_CHECK_EQUAL(reg->decimals, 0);
        BOOST_CHECK_EQUAL(reg->unlock_fees_sats, 500000000u);
        BOOST_CHECK(reg->zk_vk_commitment == vk_commit);
        BOOST_CHECK_EQUAL(reg->issuance_cap_units, 100u);
        BOOST_CHECK(reg->icu_ctxt_commit == ctxt);
        BOOST_CHECK(reg->icu_plain_commit == plain);
        BOOST_CHECK(reg->kdf_salt == salt);
        BOOST_CHECK_EQUAL(reg->icu_version, 1);
        BOOST_CHECK_EQUAL(reg->icu_visibility, 0);
        BOOST_CHECK(reg->core_policy_commit == core_commit);
    };
    check("ACME");        // root ticker
    check("ACME.C150K");  // one-hop child (ROOT.SUFFIX)
}

// §6.1/§6.2 — the TSC-ICU-META-1 container carries the EXACT §2 descriptor bytes in a machine band, is
// canonically sorted, and mirrors the §2 fields in the display termsheet. This is the on-chain bundle
// that makes a registered series "import and prove" reliable, not just listable-looking.
BOOST_AUTO_TEST_CASE(icu_metadata_band_carries_exact_descriptor)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const std::vector<unsigned char> bytes = BuildOptionSeriesIcuMetadata(t);
    const std::string json(bytes.begin(), bytes.end());

    // Canonical JSON: top-level keys sorted (optseries < spec < termsheet), so it starts with optseries.
    BOOST_CHECK(json.rfind("{\"optseries\":", 0) == 0);

    UniValue meta;
    BOOST_REQUIRE(meta.read(json));
    BOOST_REQUIRE(meta.isObject());
    BOOST_CHECK_EQUAL(meta["spec"].get_str(), "TSC-ICU-META-1");

    const UniValue& opt = meta["optseries"];
    BOOST_CHECK_EQUAL(opt["spec"].get_str(), "TSC-ICU-OPTSERIES-1");
    BOOST_CHECK_EQUAL(opt["parse_version"].getInt<int>(), 1);
    // §6.2: the band MUST carry the exact §2 descriptor hex (the same bytes fed to §3's TaggedHash).
    const std::string desc_hex = opt["descriptor"].get_str();
    BOOST_CHECK_EQUAL(desc_hex, HexStr(SerializeOptionDescriptor(t)));
    BOOST_CHECK(ParseHex(desc_hex) == SerializeOptionDescriptor(t));

    // The termsheet mirrors §2 fields (display only; payout capped at the per-lot IM).
    const UniValue& ts = meta["termsheet"];
    BOOST_CHECK_EQUAL(ts["spec"].get_str(), "TSC-ICU-TERMSHEET-1");
    BOOST_CHECK_EQUAL(ts["lot_count"].getInt<int64_t>(), static_cast<int64_t>(t.lot_count));
    BOOST_CHECK_EQUAL(ts["lot_im_sats"].getInt<int64_t>(), static_cast<int64_t>(t.lot_im_sats));
    BOOST_CHECK_EQUAL(ts["payout_cap_per_lot_sats"].getInt<int64_t>(), static_cast<int64_t>(t.lot_im_sats));
    BOOST_CHECK_EQUAL(ts["strike_nbits"].getInt<int64_t>(), static_cast<int64_t>(t.strike_nbits));
}

// §3 verifier core — the pre-purchase fraud check. Parsing the on-chain descriptor recovers the exact
// terms, and authenticity is cryptographic: the recovered terms recompute the SAME asset_id, while any
// tampered byte yields a DIFFERENT asset_id (so a fraudster cannot show benign terms for the asset you
// buy). Also walks the full path: pull the descriptor out of the ICU band, re-derive, confirm.
BOOST_AUTO_TEST_CASE(descriptor_parse_roundtrip_and_authenticity)
{
    const OptionSeriesTerms t = MakeSettlementSeriesTerms();
    const std::vector<unsigned char> desc = SerializeOptionDescriptor(t);
    const uint256 asset_id = ComputeOptionSeriesId(t);

    auto parsed = ParseOptionSeriesDescriptor(desc);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->writer_key == t.writer_key);
    BOOST_CHECK_EQUAL(parsed->descriptor_version, t.descriptor_version);
    BOOST_CHECK_EQUAL(parsed->issuance_mode, t.issuance_mode);
    BOOST_CHECK_EQUAL(parsed->leaf_set, t.leaf_set);
    BOOST_CHECK_EQUAL(parsed->strike_nbits, t.strike_nbits);
    BOOST_CHECK_EQUAL(parsed->fixing_height, t.fixing_height);
    BOOST_CHECK_EQUAL(parsed->settle_lock_height, t.settle_lock_height);
    BOOST_CHECK_EQUAL(parsed->lambda_q, t.lambda_q);
    BOOST_CHECK_EQUAL(parsed->lot_im_sats, t.lot_im_sats);
    BOOST_CHECK_EQUAL(parsed->lot_count, t.lot_count);
    BOOST_CHECK_EQUAL(parsed->reference_premium_sats, t.reference_premium_sats);
    BOOST_CHECK(parsed->series_salt == t.series_salt);
    BOOST_CHECK(SerializeOptionDescriptor(*parsed) == desc);
    BOOST_CHECK(ComputeOptionSeriesId(*parsed) == asset_id);   // AUTHENTIC

    // Wrong length is rejected outright.
    BOOST_CHECK(!ParseOptionSeriesDescriptor(std::span<const unsigned char>(desc.data(), 102)).has_value());

    // Tamper one strike byte -> a DIFFERENT asset_id: fraud is cryptographically detectable.
    std::vector<unsigned char> tampered = desc;
    tampered[35] ^= 0x01;
    auto p2 = ParseOptionSeriesDescriptor(tampered);
    BOOST_REQUIRE(p2.has_value());
    BOOST_CHECK(ComputeOptionSeriesId(*p2) != asset_id);       // FRAUD DETECTED

    // Full verifier path: pull the descriptor straight out of the on-chain ICU band, re-derive, check.
    const auto band = BuildOptionSeriesIcuMetadata(t);
    UniValue meta;
    BOOST_REQUIRE(meta.read(std::string(band.begin(), band.end())));
    const std::vector<unsigned char> from_icu = ParseHex(meta["optseries"]["descriptor"].get_str());
    auto p3 = ParseOptionSeriesDescriptor(from_icu);
    BOOST_REQUIRE(p3.has_value());
    BOOST_CHECK(ComputeOptionSeriesId(*p3) == asset_id);       // ICU band -> authentic terms
}

BOOST_AUTO_TEST_SUITE_END()
