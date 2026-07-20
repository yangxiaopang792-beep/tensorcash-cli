// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for KYC asset signature hash enforcement (Phase 1 of ZK_WITNESS.md).
//
// Pattern #15 extension: All KYC asset inputs must use output-binding sighashes
// (SIGHASH_ALL or Taproot DEFAULT) to prevent proof-output rebinding attacks.
//
// This mirrors the ICU sighash enforcement (tx_verify.cpp:303-321) but applies
// to holder-signed KYC asset inputs rather than issuer-signed ICU inputs.

#include <boost/test/unit_test.hpp>

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <consensus/zk_utils.h>
#include <primitives/transaction.h>
#include <coins.h>
#include <serialize.h>
#include <txdb.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>

#include <assets/asset.h>
#include <assets/registry.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <addresstype.h>

#include <cstring>
#include <optional>
#include <vector>

namespace {

using AID = uint256;

[[maybe_unused]] std::vector<unsigned char> MakeKycIssuerReg(const AID& id, const uint256& vk_commitment)
{
    // KYC asset requires: policy.required = true (KYC_REQUIRED flag)
    // and a non-null vk_commitment
    return test_util::BuildV1IssuerReg(
        id,
        /*policy_bits=*/assets::KYC_REQUIRED | assets::MINT_ALLOWED,
        /*allowed_spk=*/assets::SPK_DEFAULT_ALLOWED,
        /*ticker=*/"",
        /*decimals=*/0xFF,
        /*unlock_fees=*/std::numeric_limits<uint64_t>::max(),
        /*kyc_flags=*/0,
        /*vk_commitment=*/vk_commitment,
        /*max_root_age=*/288
    );
}

std::vector<unsigned char> MakeAssetTag(const AID& id, uint64_t amount)
{
    return test_util::BuildAssetTag(id, amount);
}

std::vector<unsigned char> MakeSchnorrSig(unsigned char fill, std::optional<unsigned char> sighash)
{
    std::vector<unsigned char> sig(64, fill);
    if (sighash.has_value()) {
        sig.push_back(*sighash);
    }
    return sig;
}

std::vector<unsigned char> MakeDerSig(unsigned char sighash)
{
    std::vector<unsigned char> sig;
    sig.reserve(72);
    sig.push_back(0x30);
    sig.push_back(0x44); // total length of R/S fields
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

std::vector<unsigned char> MakeGroth16Proof()
{
    return std::vector<unsigned char>(192, 0xAA); // Mock Groth16 proof (A||B||C)
}

std::vector<unsigned char> MakePublicInputs()
{
    return std::vector<unsigned char>(assets::GROTH16_MIN_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE, 0xBB); // Mock public inputs (4 × 32 bytes)
}

// 6-input (HDv1) mock public inputs. Content is junk (0xBB); used to exercise the
// F1 layout gate, which is content-independent.
std::vector<unsigned char> MakePublicInputs6()
{
    return std::vector<unsigned char>(assets::GROTH16_HDV1_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE, 0xBB); // 6 × 32 bytes
}

// Build a proof output carrying an explicit public-inputs blob (lets tests choose
// the public-input count to exercise the F1 layout gate).
void AppendProofOutputWithInputs(CMutableTransaction& mtx, const AID& asset_id,
                                 const std::vector<unsigned char>& public_inputs)
{
    CScript proof_script = CScript() << OP_RETURN;
    CTxOut proof_out(0, proof_script);
    proof_out.vExt = test_util::BuildZkProofPayload(asset_id, MakeGroth16Proof(), public_inputs);
    mtx.vout.push_back(std::move(proof_out));
}

void AppendProofOutput(CMutableTransaction& mtx, const AID& asset_id)
{
    CScript proof_script = CScript() << OP_RETURN;
    CTxOut proof_out(0, proof_script);
    proof_out.vExt = test_util::BuildZkProofPayload(asset_id, MakeGroth16Proof(), MakePublicInputs());
    mtx.vout.push_back(std::move(proof_out));
}

struct KycSighashTestContext {
    CCoinsViewDB db;
    CCoinsViewCache view;
    AID asset_id;
    uint256 vk_commitment;
    COutPoint kyc_utxo_prevout;
    CTxOut kyc_utxo;

    KycSighashTestContext()
        : db({.path = "kyc-sighash", .cache_bytes = 1 << 20, .memory_only = true}, {})
        , view(&db)
    {
        // Generate mock asset ID and VK commitment
        asset_id.SetNull();
        asset_id.begin()[0] = 0xCC;
        vk_commitment.SetNull();
        vk_commitment.begin()[0] = 0xDD;

        // Create a KYC asset UTXO
        Txid prev_txid;
        memset(const_cast<std::byte*>(prev_txid.data()), 0x55, prev_txid.size());
        kyc_utxo_prevout = COutPoint(prev_txid, 0);

        kyc_utxo = CTxOut(2000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
        kyc_utxo.vExt = MakeAssetTag(asset_id, 1000);

        view.AddCoin(kyc_utxo_prevout, Coin(kyc_utxo, /*height=*/10, /*coinbase=*/false), /*overwrite=*/false);

        // Register the asset policy with KYC enforcement
        // Write asset registry entry with KYC_REQUIRED policy bit
        AssetRegistryEntry registry_entry;
        registry_entry.policy_bits = assets::KYC_REQUIRED | assets::MINT_ALLOWED;
        registry_entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
        registry_entry.has_kyc = true;
        registry_entry.zk_vk_commitment = vk_commitment;
        registry_entry.max_root_age = 288;
        registry_entry.tfr_flags = 0;

        // Set compliance root commit (required for KYC assets)
        // Using zero root with height 100 to match what tests pass in BuildComplianceField
        auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
        std::copy(compliance_bytes.begin(), compliance_bytes.end(), registry_entry.compliance_root_commit.begin());
        bool written = db.WriteAssetPolicy(asset_id, registry_entry);
        assert(written && "Failed to write asset policy to database");

        // Flush the database to ensure the write is visible
        // (though LevelDB should handle this automatically for in-memory databases)

        StoreMockVK();
    }

    // Helper: Store mock verifying key in DB (required for proof verification to proceed past sighash check)
    void StoreMockVK()
    {
        std::vector<unsigned char> mock_vk(200, 0xEE); // Mock VK bytes
        db.WriteZkVerifyingKey(vk_commitment, mock_vk);
    }
};

bool RunCheck(const CTransaction& tx, CCoinsViewCache& view, std::string& reason)
{
    CAmount fee{0};
    TxValidationState state;
    bool result = Consensus::CheckTxInputs(tx, state, view, /*height=*/200, fee);
    if (!result) {
        reason = state.GetRejectReason();
    }

    return result;
}

CTransaction BuildKycAssetSpendTx(
    const COutPoint& prevout,
    const CTxOut& output,
    const std::optional<std::vector<unsigned char>>& signature,
    const AID& asset_id,
    bool include_zk_proof = true)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(prevout);

    // TLV-based proof transport: witness contains only standard spend elements
    if (signature.has_value()) {
        mtx.vin[0].scriptWitness.stack.push_back(*signature);
    }
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02)); // mock pubkey

    // Add primary asset output (retains AssetTag TLV)
    mtx.vout.push_back(output);
    if (include_zk_proof) {
        AppendProofOutput(mtx, asset_id);
    }

    return CTransaction(mtx);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_kyc_sighash_tests, BasicTestingSetup)

// Test: Verify asset policy is correctly written and read from database
BOOST_AUTO_TEST_CASE(kyc_policy_database_sanity_check)
{
    KycSighashTestContext ctx;

    // Verify policy was written
    AssetRegistryEntry read_entry;
    bool found = ctx.db.ReadAssetPolicy(ctx.asset_id, read_entry);

    BOOST_CHECK_MESSAGE(found, "Asset policy not found in database");
    BOOST_CHECK_MESSAGE(read_entry.has_kyc, "Asset policy has_kyc is false");
    BOOST_CHECK_MESSAGE((read_entry.policy_bits & assets::KYC_REQUIRED), "Asset policy missing KYC_REQUIRED bit");
    BOOST_CHECK_MESSAGE(!read_entry.zk_vk_commitment.IsNull(), "Asset policy vk_commitment is null");

    // Verify transaction structure has asset tags in both input and output
    auto sig = MakeSchnorrSig(/*fill=*/0x01, /*sighash=*/SIGHASH_ALL);
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, sig, ctx.asset_id);

    // Check input UTXO has asset tag
    const Coin& coin = ctx.view.AccessCoin(tx.vin[0].prevout);
    auto input_tag = assets::ParseAssetTag(coin.out.vExt);
    BOOST_CHECK_MESSAGE(input_tag.has_value(), "Input UTXO missing asset tag");
    if (input_tag) {
        BOOST_CHECK_MESSAGE(input_tag->id == ctx.asset_id, "Input asset ID mismatch");
    }

    // Check output has asset tag
    auto output_tag = assets::ParseAssetTag(tx.vout[0].vExt);
    BOOST_CHECK_MESSAGE(output_tag.has_value(), "Output missing asset tag");
    if (output_tag) {
        BOOST_CHECK_MESSAGE(output_tag->id == ctx.asset_id, "Output asset ID mismatch");
    }
}

// Test: KYC asset spends with SIGHASH_ALL (Schnorr explicit) are accepted
BOOST_AUTO_TEST_CASE(kyc_sighash_all_explicit_accepted)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x01, /*sighash=*/SIGHASH_ALL);
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, sig, ctx.asset_id);
    std::string reason;

    // Note: This test focuses on sighash validation. Full proof verification would require
    // complete ZK infrastructure setup (VK, public inputs matching, etc.).
    // The sighash check happens BEFORE proof verification, so we test in isolation.
    BOOST_CHECK(RunCheck(tx, ctx.view, reason) || reason != "zk-invalid-sighash");
}

// Test: KYC asset spends with SIGHASH_DEFAULT (Taproot implicit) are accepted
BOOST_AUTO_TEST_CASE(kyc_sighash_default_taproot_accepted)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x02, /*sighash=*/std::nullopt); // 64-byte = DEFAULT
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, sig, ctx.asset_id);
    std::string reason;
    BOOST_CHECK(RunCheck(tx, ctx.view, reason) || reason != "zk-invalid-sighash");
}

// Test: KYC asset spends with ANYONECANPAY are rejected (consensus error)
BOOST_AUTO_TEST_CASE(kyc_sighash_anyonecanpay_rejected)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x03, /*sighash=*/static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, sig, ctx.asset_id);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// Test: KYC asset spends with SIGHASH_SINGLE are rejected
BOOST_AUTO_TEST_CASE(kyc_sighash_single_rejected)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x04, /*sighash=*/SIGHASH_SINGLE);
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, sig, ctx.asset_id);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// Test: KYC asset spends with SIGHASH_NONE are rejected
BOOST_AUTO_TEST_CASE(kyc_sighash_none_rejected)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x05, /*sighash=*/SIGHASH_NONE);
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, sig, ctx.asset_id);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// Test: ECDSA signatures with SIGHASH_ALL are accepted
BOOST_AUTO_TEST_CASE(kyc_ecdsa_sighash_all_accepted)
{
    KycSighashTestContext ctx;
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin[0].scriptSig << MakeDerSig(SIGHASH_ALL);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02)); // pubkey

    // Add ZK_PROOF_PAYLOAD TLV to output
    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason) || reason != "zk-invalid-sighash");
}

// Test: ECDSA signatures with ANYONECANPAY are rejected
BOOST_AUTO_TEST_CASE(kyc_ecdsa_anyonecanpay_rejected)
{
    KycSighashTestContext ctx;
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin[0].scriptSig << MakeDerSig(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));

    // Add ZK_PROOF_PAYLOAD TLV to output
    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// Test: Taproot annex is correctly handled (skipped during sighash scan per BIP341)
BOOST_AUTO_TEST_CASE(kyc_taproot_annex_handled)
{
    KycSighashTestContext ctx;
    std::vector<unsigned char> annex(64, 0x51);
    annex.front() = 0x50; // Annex marker
    auto sig = MakeSchnorrSig(0x07, std::nullopt); // SIGHASH_DEFAULT

    CMutableTransaction mtx;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin[0].scriptWitness.stack.push_back(annex);  // Annex first
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02)); // pubkey

    // Add ZK_PROOF_PAYLOAD TLV to output
    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason) || reason != "zk-invalid-sighash");
}

// Test: Mixed sighashes in multisig (one good, one bad) are rejected
BOOST_AUTO_TEST_CASE(kyc_multisig_mixed_sighash_rejected)
{
    KycSighashTestContext ctx;
    CMutableTransaction mtx;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);

    auto good_sig = MakeSchnorrSig(0x08, SIGHASH_ALL);
    auto bad_sig = MakeSchnorrSig(0x09, static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));

    mtx.vin[0].scriptWitness.stack.push_back(good_sig);
    mtx.vin[0].scriptWitness.stack.push_back(bad_sig);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(105, 0x52)); // mock redeemScript

    // Add ZK_PROOF_PAYLOAD TLV to output
    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// Test: No signature in witness (unsigned transaction) - sighash check is skipped
// (This allows for unsigned txs during construction; script execution will fail later)
BOOST_AUTO_TEST_CASE(kyc_no_signature_allowed_for_construction)
{
    KycSighashTestContext ctx;
    CTransaction tx = BuildKycAssetSpendTx(ctx.kyc_utxo_prevout, ctx.kyc_utxo, std::nullopt, ctx.asset_id);
    std::string reason;

    // Sighash check only triggers if saw_signature=true. Unsigned txs pass the sighash
    // check but will fail at script execution or other validation stages.
    BOOST_CHECK(RunCheck(tx, ctx.view, reason) || reason != "zk-invalid-sighash");
}

// F2 regression: a ONE-INPUT tx that merely sets the ROTATION_TX_FLAG version bit
// must NOT receive the sighash exemption. IsRotationTx() is author-controlled and the
// compensating rotation structural validation is gated on vin.size() > 1, so a 1-input
// "rotation" would otherwise skip both the output-binding sighash rule and the rotation
// checks — reopening proof/output rebinding. The fix (tx_verify.cpp) requires a genuine
// multi-input rotation for the exemption, so this weak-sighash spend is now rejected.
BOOST_AUTO_TEST_CASE(kyc_rotation_oneinput_not_exempt_F2)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(0x0A, static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG; // self-flagged rotation
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout); // single input
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));

    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// Also covers SIGHASH_NONE / SIGHASH_SINGLE on a 1-input self-flagged rotation:
// the consensus rule bans non-ALL/DEFAULT base too, and the exemption no longer applies.
BOOST_AUTO_TEST_CASE(kyc_rotation_oneinput_sighash_none_rejected_F2)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(0x0A, SIGHASH_NONE);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));

    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// ---- F2 per-input ballot waiver helpers ----------------------------------------------
//
// The sighash waiver is per-input: it is granted ONLY to an input that is a validated
// rotation ballot (the tx has the rotation shape for THIS asset, and the input is a
// self-bounce paired to a proposal-hash output at the same index). These helpers build
// such ballots so the tests can break exactly one condition at a time.

// Register a KYC-required asset (policy + mock VK) into the test db.
static void RegisterKycAssetForTest(KycSighashTestContext& ctx, const uint256& asset_id, const uint256& vk_commitment)
{
    AssetRegistryEntry e;
    e.policy_bits = assets::KYC_REQUIRED | assets::MINT_ALLOWED;
    e.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
    e.has_kyc = true;
    e.zk_vk_commitment = vk_commitment;
    e.max_root_age = 288;
    e.tfr_flags = 0;
    auto cb = Consensus::BuildComplianceField(uint256(), 100);
    std::copy(cb.begin(), cb.end(), e.compliance_root_commit.begin());
    ctx.db.WriteAssetPolicy(asset_id, e);
    std::vector<unsigned char> mock_vk(200, 0xEE);
    ctx.db.WriteZkVerifyingKey(vk_commitment, mock_vk);
}

// Add an asset UTXO to the view; return its outpoint.
static COutPoint AddAssetUtxoForTest(KycSighashTestContext& ctx, unsigned char fill, uint32_t n,
                                     const uint256& asset_id, uint64_t units, CAmount sats, int height)
{
    Txid t; memset(const_cast<std::byte*>(t.data()), fill, t.size());
    COutPoint op(t, n);
    CTxOut u(sats, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    u.vExt = test_util::BuildAssetTag(asset_id, units);
    ctx.view.AddCoin(op, Coin(u, height, /*coinbase=*/false), /*overwrite=*/false);
    return op;
}

// Positive: a genuine ballot (self-bounce paired to a proposal-hash output) signed with
// SIGHASH_SINGLE|ANYONECANPAY is exempt — must NOT be rejected for sighash.
BOOST_AUTO_TEST_CASE(kyc_rotation_ballot_paired_exempt)
{
    KycSighashTestContext ctx;
    const uint64_t units = 1500;
    COutPoint ballot_prevout = AddAssetUtxoForTest(ctx, 0x88, 0, ctx.asset_id, units, 2500, 12);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);  // input 0: strict KYC input
    mtx.vin.emplace_back(ballot_prevout);        // input 1: ballot

    CTxOut issuer_reg_out(0, CScript() << OP_RETURN);
    issuer_reg_out.vExt = MakeKycIssuerReg(ctx.asset_id, ctx.vk_commitment);
    mtx.vout.push_back(issuer_reg_out);          // vout[0] = IssuerReg for rotated asset

    const uint256 ph = ComputeRotationProposalHash(mtx); // uses vin[0].prevout + vout[0].vExt

    CTxOut ballot_out(2500, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    ballot_out.vExt = assets::BuildAssetTagWithProposal(ctx.asset_id, units, ph, 0u, false, (uint8_t)0);
    mtx.vout.push_back(ballot_out);              // vout[1] = paired ballot self-bounce
    AppendProofOutput(mtx, ctx.asset_id);

    mtx.vin[0].scriptWitness.stack.push_back(MakeSchnorrSig(0x0B, SIGHASH_ALL));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vin[1].scriptWitness.stack.push_back(MakeSchnorrSig(0x0A, static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)));
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason) || reason != "zk-invalid-sighash");
}

// SIGHASH_NONE on a ballot input is rejected even when the pairing is valid: a ballot may
// use SINGLE|ANYONECANPAY (commits its own output), never NONE.
BOOST_AUTO_TEST_CASE(kyc_rotation_ballot_sighash_none_rejected)
{
    KycSighashTestContext ctx;
    const uint64_t units = 1500;
    COutPoint ballot_prevout = AddAssetUtxoForTest(ctx, 0x89, 0, ctx.asset_id, units, 2500, 12);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin.emplace_back(ballot_prevout);

    CTxOut issuer_reg_out(0, CScript() << OP_RETURN);
    issuer_reg_out.vExt = MakeKycIssuerReg(ctx.asset_id, ctx.vk_commitment);
    mtx.vout.push_back(issuer_reg_out);
    const uint256 ph = ComputeRotationProposalHash(mtx);
    CTxOut ballot_out(2500, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    ballot_out.vExt = assets::BuildAssetTagWithProposal(ctx.asset_id, units, ph, 0u, false, (uint8_t)0);
    mtx.vout.push_back(ballot_out);
    AppendProofOutput(mtx, ctx.asset_id);

    mtx.vin[0].scriptWitness.stack.push_back(MakeSchnorrSig(0x0B, SIGHASH_ALL));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vin[1].scriptWitness.stack.push_back(MakeSchnorrSig(0x0A, SIGHASH_NONE)); // weak: rejected
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    // Rejected either at the weak-sighash check or the burn/ICU-authorization precursor.
    BOOST_CHECK(reason == "zk-invalid-sighash" || reason == "asset-burn-needs-icu");
}

// A non-ballot input of the rotated asset (no valid pairing — here a wrong-amount output)
// gets NO waiver: ANYONECANPAY on it is rejected.
BOOST_AUTO_TEST_CASE(kyc_rotation_nonballot_assetA_input_rejected)
{
    KycSighashTestContext ctx;
    const uint64_t units = 1500;
    COutPoint in_prevout = AddAssetUtxoForTest(ctx, 0x8A, 0, ctx.asset_id, units, 2500, 12);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin.emplace_back(in_prevout);

    CTxOut issuer_reg_out(0, CScript() << OP_RETURN);
    issuer_reg_out.vExt = MakeKycIssuerReg(ctx.asset_id, ctx.vk_commitment);
    mtx.vout.push_back(issuer_reg_out);
    const uint256 ph = ComputeRotationProposalHash(mtx);
    CTxOut out1(2500, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    out1.vExt = assets::BuildAssetTagWithProposal(ctx.asset_id, units + 1, ph, 0u, false, (uint8_t)0); // amount mismatch -> not a ballot
    mtx.vout.push_back(out1);
    AppendProofOutput(mtx, ctx.asset_id);

    mtx.vin[0].scriptWitness.stack.push_back(MakeSchnorrSig(0x0B, SIGHASH_ALL));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vin[1].scriptWitness.stack.push_back(MakeSchnorrSig(0x0A, static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)));
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    // Rejected either at the weak-sighash check or the burn/ICU-authorization precursor.
    BOOST_CHECK(reason == "zk-invalid-sighash" || reason == "asset-burn-needs-icu");
}

// A correctly-paired output but with the WRONG proposal_hash is not a ballot -> no waiver.
BOOST_AUTO_TEST_CASE(kyc_rotation_wrong_proposal_hash_rejected)
{
    KycSighashTestContext ctx;
    const uint64_t units = 1500;
    COutPoint in_prevout = AddAssetUtxoForTest(ctx, 0x8B, 0, ctx.asset_id, units, 2500, 12);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin.emplace_back(in_prevout);

    CTxOut issuer_reg_out(0, CScript() << OP_RETURN);
    issuer_reg_out.vExt = MakeKycIssuerReg(ctx.asset_id, ctx.vk_commitment);
    mtx.vout.push_back(issuer_reg_out);
    uint256 wrong_ph; wrong_ph.begin()[0] = 0xFF; // not ComputeRotationProposalHash(mtx)
    CTxOut out1(2500, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    out1.vExt = assets::BuildAssetTagWithProposal(ctx.asset_id, units, wrong_ph, 0u, false, (uint8_t)0);
    mtx.vout.push_back(out1);
    AppendProofOutput(mtx, ctx.asset_id);

    mtx.vin[0].scriptWitness.stack.push_back(MakeSchnorrSig(0x0B, SIGHASH_ALL));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vin[1].scriptWitness.stack.push_back(MakeSchnorrSig(0x0A, static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)));
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    // Rejected either at the weak-sighash check or the burn/ICU-authorization precursor.
    BOOST_CHECK(reason == "zk-invalid-sighash" || reason == "asset-burn-needs-icu");
}

// Cross-asset: a genuine rotation of asset A does NOT waive a weak-sighash KYC input of an
// unrelated asset B in the same tx.
BOOST_AUTO_TEST_CASE(kyc_rotation_assetB_input_not_waived)
{
    KycSighashTestContext ctx; // asset A
    uint256 assetB; assetB.SetNull(); assetB.begin()[0] = 0xB0;
    uint256 vkB;    vkB.SetNull();    vkB.begin()[0] = 0xB1;
    RegisterKycAssetForTest(ctx, assetB, vkB);
    COutPoint b_prevout = AddAssetUtxoForTest(ctx, 0x8C, 0, assetB, 1000, 2000, 12);

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION | CTransaction::ROTATION_TX_FLAG;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout); // input 0: asset A, strict
    mtx.vin.emplace_back(b_prevout);            // input 1: asset B, weak (ANYONECANPAY)

    CTxOut issuer_reg_out(0, CScript() << OP_RETURN);
    issuer_reg_out.vExt = MakeKycIssuerReg(ctx.asset_id, ctx.vk_commitment); // rotation of A
    mtx.vout.push_back(issuer_reg_out);
    CTxOut a_out(2000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    a_out.vExt = MakeAssetTag(ctx.asset_id, 1000);
    mtx.vout.push_back(a_out);
    CTxOut b_out(2000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    b_out.vExt = MakeAssetTag(assetB, 1000);
    mtx.vout.push_back(b_out);
    AppendProofOutput(mtx, ctx.asset_id); // A passes proof-presence; B fails earlier at sighash

    mtx.vin[0].scriptWitness.stack.push_back(MakeSchnorrSig(0x0B, SIGHASH_ALL));
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vin[1].scriptWitness.stack.push_back(MakeSchnorrSig(0x0A, static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY)));
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

// F1 regression: a KYC asset spend carrying a legacy 4-input proof must be rejected.
// 4-input ("standard") proofs have no output-key binding and are bearer tokens; a
// non-KYC holder could replay a copied valid proof. Consensus now rejects any KYC
// proof whose layout is not the 6-input HDv1 family. Uses a valid SIGHASH_ALL so the
// rejection is the layout gate, not the sighash rule.
BOOST_AUTO_TEST_CASE(kyc_legacy_4input_proof_rejected_F1)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x01, /*sighash=*/SIGHASH_ALL);

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutputWithInputs(mtx, ctx.asset_id, MakePublicInputs()); // 4 inputs

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "kyc-proof-not-hdv1");
}

// F1 companion: a 6-input (HDv1) proof passes the layout gate. It will still fail
// later (mock proof content / non-P2TR prevout), but NOT with "kyc-proof-not-hdv1".
BOOST_AUTO_TEST_CASE(kyc_hdv1_6input_passes_layout_gate_F1)
{
    KycSighashTestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x01, /*sighash=*/SIGHASH_ALL);

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    mtx.vout.push_back(ctx.kyc_utxo);
    AppendProofOutputWithInputs(mtx, ctx.asset_id, MakePublicInputs6()); // 6 inputs

    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason) || reason != "kyc-proof-not-hdv1");
}

// Test: Multiple KYC asset inputs, all with valid sighashes
BOOST_AUTO_TEST_CASE(kyc_multiple_inputs_all_valid)
{
    KycSighashTestContext ctx;

    // Create second UTXO
    Txid prev_txid2;
    memset(const_cast<std::byte*>(prev_txid2.data()), 0x66, prev_txid2.size());
    COutPoint prevout2(prev_txid2, 1);
    CTxOut utxo2(3000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    utxo2.vExt = MakeAssetTag(ctx.asset_id, 2000);
    ctx.view.AddCoin(prevout2, Coin(utxo2, /*height=*/15, /*coinbase=*/false), /*overwrite=*/false);

    auto sig1 = MakeSchnorrSig(0x0B, SIGHASH_ALL);
    auto sig2 = MakeSchnorrSig(0x0C, std::nullopt); // SIGHASH_DEFAULT

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin.emplace_back(prevout2);

    // Input 0 witness (TLV-based: only sig + pubkey)
    mtx.vin[0].scriptWitness.stack.push_back(sig1);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));

    // Input 1 witness (TLV-based: only sig + pubkey)
    mtx.vin[1].scriptWitness.stack.push_back(sig2);
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    // Output with ZK_PROOF_PAYLOAD TLV
    CTxOut combined_out(5000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    combined_out.vExt = MakeAssetTag(ctx.asset_id, 3000);
    mtx.vout.push_back(combined_out);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason) || reason != "zk-invalid-sighash");
}

// Test: Multiple KYC asset inputs, one with invalid sighash
BOOST_AUTO_TEST_CASE(kyc_multiple_inputs_one_invalid)
{
    KycSighashTestContext ctx;

    // Create second UTXO
    Txid prev_txid2;
    memset(const_cast<std::byte*>(prev_txid2.data()), 0x77, prev_txid2.size());
    COutPoint prevout2(prev_txid2, 2);
    CTxOut utxo2(4000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    utxo2.vExt = MakeAssetTag(ctx.asset_id, 3000);
    ctx.view.AddCoin(prevout2, Coin(utxo2, /*height=*/20, /*coinbase=*/false), /*overwrite=*/false);

    auto sig1 = MakeSchnorrSig(0x0D, SIGHASH_ALL); // Valid
    auto sig2 = MakeSchnorrSig(0x0E, SIGHASH_SINGLE); // Invalid

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.kyc_utxo_prevout);
    mtx.vin.emplace_back(prevout2);

    // Input 0 witness (valid, TLV-based: only sig + pubkey)
    mtx.vin[0].scriptWitness.stack.push_back(sig1);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x02));

    // Input 1 witness (invalid sighash, TLV-based: only sig + pubkey)
    mtx.vin[1].scriptWitness.stack.push_back(sig2);
    mtx.vin[1].scriptWitness.stack.push_back(std::vector<unsigned char>(33, 0x03));

    // Output with ZK_PROOF_PAYLOAD TLV
    CTxOut combined_out(6000, GetScriptForDestination(WitnessV0KeyHash(uint160())));
    combined_out.vExt = MakeAssetTag(ctx.asset_id, 4000);
    mtx.vout.push_back(combined_out);
    AppendProofOutput(mtx, ctx.asset_id);

    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "zk-invalid-sighash");
}

BOOST_AUTO_TEST_SUITE_END()
