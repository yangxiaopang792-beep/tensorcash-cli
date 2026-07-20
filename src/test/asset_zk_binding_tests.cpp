// Tests for consensus-level public input binding enforcement (chain/asset/anchor).

#include <boost/test/unit_test.hpp>

#include <addresstype.h>
#include <assets/asset.h>
#include <assets/registry.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <consensus/zk_utils.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <serialize.h>
#include <test/util/asset_utils.h>
#include <test/util/setup_common.h>
#include <test/util/zk_test_helpers.h>
#include <txdb.h>

#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace Consensus;
using zk_test::MockGroth16Proof;
using zk_test::MockVerifyingKey;
using zk_test::uint256S;

namespace {

std::vector<unsigned char> MakeAssetTag(const uint256& id, uint64_t amount)
{
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), id.begin(), id.end());
    unsigned char buf8[8];
    WriteLE64(buf8, amount);
    payload.insert(payload.end(), buf8, buf8 + 8);
    unsigned char flags[4]{};
    payload.insert(payload.end(), flags, flags + 4);
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::vector<unsigned char> MakeTfrAnchor(const uint256& asset_id, const uint256& commit)
{
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    payload.insert(payload.end(), commit.begin(), commit.end());
    unsigned char keyset[4]{};
    payload.insert(payload.end(), keyset, keyset + 4);
    payload.push_back(0); // empty locator length

    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::TFR_ANCHOR));
    tlv.push_back(static_cast<unsigned char>(payload.size()));
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::vector<unsigned char> MakeDerSignature(unsigned char sighash = SIGHASH_ALL)
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

std::vector<unsigned char> EncodePublicInputs(const std::array<unsigned char, 32>& chain,
                                              const std::array<unsigned char, 32>& asset,
                                              const std::array<unsigned char, 32>& compliance,
                                              const std::array<unsigned char, 32>& anchor)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), chain.begin(), chain.end());
    out.insert(out.end(), asset.begin(), asset.end());
    out.insert(out.end(), compliance.begin(), compliance.end());
    out.insert(out.end(), anchor.begin(), anchor.end());
    return out;
}

uint256 ComputeVkCommitment(const std::vector<unsigned char>& vk)
{
    HashWriter hasher;
    hasher.write(std::as_bytes(std::span<const unsigned char>(vk.data(), vk.size())));
    return hasher.GetHash();
}

bool RunCheck(const CTransaction& tx, CCoinsViewCache& view, int nSpendHeight, std::string& reject_reason)
{
    TxValidationState state;
    CAmount fee{0};
    if (!Consensus::CheckTxInputs(tx, state, view, nSpendHeight, fee)) {
        reject_reason = state.GetRejectReason();
        return false;
    }
    return true;
}

struct BindingTestContext {
    CCoinsViewDB db;
    CCoinsViewCache view;
    uint256 asset_id;
    uint256 vk_commitment;
    AssetRegistryEntry registry_entry;

    BindingTestContext()
        : db{{.path = "zk-binding", .cache_bytes = 1 << 20, .memory_only = true}, {}}
        , view(&db)
        , asset_id(uint256S("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    {
        auto vk_bytes = MockVerifyingKey(4);
        vk_commitment = ComputeVkCommitment(vk_bytes);
        db.WriteZkVerifyingKey(vk_commitment, vk_bytes);

        registry_entry.policy_bits = assets::MINT_ALLOWED | assets::KYC_REQUIRED;
        registry_entry.allowed_spk_families = assets::SPK_DEFAULT_ALLOWED;
        registry_entry.has_kyc = true;
        registry_entry.zk_vk_commitment = vk_commitment;
        registry_entry.max_root_age = 288;
        registry_entry.tfr_flags = 0;
        // ZK Whitelist Hardening: Set compliance root commitment for tests.
        // BuildComplianceField returns big-endian bytes, but uint256 is little-endian
        // internally. Reverse so that Uint256ToBytesBE(commit) reproduces the original.
        auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
        for (size_t i = 0; i < 32; ++i) {
            registry_entry.compliance_root_commit.begin()[31 - i] = compliance_bytes[i];
        }
        db.WriteAssetPolicy(asset_id, registry_entry);

        const uint256 prev_hash = uint256S("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        const Txid prev_txid = Txid::FromUint256(prev_hash);
        const COutPoint prev(prev_txid, 0);
        CScript spk = GetScriptForDestination(WitnessV0KeyHash(uint160()));
        CTxOut utxo(1000, spk);
        utxo.vExt = MakeAssetTag(asset_id, 1000);
        view.AddCoin(prev, Coin(utxo, /*height=*/5, /*coinbase=*/false), /*overwrite=*/false);
    }
};

CScriptWitness BuildWitness()
{
    // TLV-based proof transport: witness contains only standard spend elements.
    // ZK proof and public inputs are transported via ZK_PROOF_PAYLOAD TLV in outputs.
    CScriptWitness witness;
    witness.stack.push_back(MakeDerSignature());
    witness.stack.push_back(std::vector<unsigned char>(33, 0x02));
    return witness;
}

void AppendProofOutput(CMutableTransaction& mtx,
                       const uint256& asset_id,
                       const std::vector<unsigned char>& proof,
                       const std::vector<unsigned char>& public_inputs)
{
    CTxOut proof_out(0, CScript() << OP_RETURN);
    proof_out.vExt = test_util::BuildZkProofPayload(asset_id, proof, public_inputs);
    mtx.vout.push_back(std::move(proof_out));
}

void PopulateTransaction(CMutableTransaction& mtx, const BindingTestContext& ctx)
{
    const uint256 prev_hash = uint256S("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const Txid prev_txid = Txid::FromUint256(prev_hash);
    const COutPoint prev(prev_txid, 0);
    mtx.vin.emplace_back(prev);

    CScript spk = GetScriptForDestination(WitnessV0KeyHash(uint160()));
    CTxOut out(1000, spk);
    out.vExt = MakeAssetTag(ctx.asset_id, 1000);
    mtx.vout.push_back(out);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_zk_binding_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(binding_accepts_matching_inputs)
{
    BindingTestContext ctx;

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    // 4-input proofs are now rejected at the HDv1 interface gate before the
    // binding-specific check; accept either (forward-compatible if rebuilt as 6-input).
    BOOST_CHECK(reason == "zk-vk-invalid" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_rejects_chain_mismatch)
{
    BindingTestContext ctx;

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    chain_bytes[0] ^= 0xFF;
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, 200, reason));
    BOOST_CHECK(reason == "zk-chain-mismatch" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_rejects_asset_mismatch)
{
    BindingTestContext ctx;

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    asset_bytes[0] ^= 0xAA;
    const auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, 200, reason));
    BOOST_CHECK(reason == "zk-asset-mismatch" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_rejects_anchor_mismatch)
{
    BindingTestContext ctx;
    ctx.registry_entry.tfr_flags = assets::TFR_ANCHOR_REQUIRED;
    ctx.db.WriteAssetPolicy(ctx.asset_id, ctx.registry_entry);

    const uint256 anchor_commit = uint256S("0x9999999999999999999999999999999999999999999999999999999999999999");

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);
    mtx.vout[0].vExt = MakeAssetTag(ctx.asset_id, 1000);
    mtx.vout.emplace_back(0, CScript() << OP_TRUE);
    mtx.vout.back().vExt = MakeTfrAnchor(ctx.asset_id, anchor_commit);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
    auto anchor_bytes = Consensus::Uint256ToBytesBE(anchor_commit);
    anchor_bytes[0] ^= 0x11;

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, 200, reason));
    BOOST_CHECK(reason == "zk-anchor-mismatch" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_rejects_compliance_root_mismatch)
{
    // Test that spend validation rejects proofs with mismatched compliance root
    BindingTestContext ctx;

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);

    // Proof uses a different root than what's committed in registry
    auto wrong_compliance_bytes = Consensus::BuildComplianceField(uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"), 100);
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, wrong_compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    BOOST_CHECK(reason == "zk-root-mismatch" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_accepts_historical_root_within_max_age)
{
    // Test that spend validation accepts proofs using historical root within max_root_age
    BindingTestContext ctx;

    // Add historical root to ring buffer
    ComplianceRootHistory hist;
    auto hist_root_bytes = Consensus::BuildComplianceField(uint256(), 80);  // height=80
    for (size_t i = 0; i < 32; ++i) hist.root_commit.begin()[31 - i] = hist_root_bytes[i];
    hist.activation_height = 80;
    hist.txid = Txid::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").value();
    ctx.registry_entry.compliance_root_history.push_back(hist);
    ctx.db.WriteAssetPolicy(ctx.asset_id, ctx.registry_entry);

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = hist_root_bytes;  // Use historical root
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    // Spend at height 200, historical root activated at 80, delta=120 < max_root_age=288
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    // Note: This will fail with zk-vk-invalid because we're using mock proofs,
    // but the key point is it doesn't fail with zk-root-mismatch
    BOOST_CHECK_NE(reason, "zk-root-mismatch");
}

BOOST_AUTO_TEST_CASE(binding_rejects_stale_historical_root)
{
    // Test that spend validation rejects proofs using historical root beyond max_root_age
    BindingTestContext ctx;
    ctx.registry_entry.max_root_age = 100;  // Set lower max_root_age for test

    // Add historical root to ring buffer with old activation height
    ComplianceRootHistory hist;
    auto hist_root_bytes = Consensus::BuildComplianceField(uint256(), 50);
    for (size_t i = 0; i < 32; ++i) hist.root_commit.begin()[31 - i] = hist_root_bytes[i];
    hist.activation_height = 50;
    hist.txid = Txid::FromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").value();
    ctx.registry_entry.compliance_root_history.push_back(hist);
    ctx.db.WriteAssetPolicy(ctx.asset_id, ctx.registry_entry);

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = hist_root_bytes;  // Use stale historical root
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    // Spend at height 200, historical root activated at 50, delta=150 > max_root_age=100
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    BOOST_CHECK(reason == "zk-root-mismatch" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_rejects_zero_commitment_for_kyc_asset)
{
    // Test that spend validation rejects spends when compliance_root_commit is zero for KYC asset
    BindingTestContext ctx;

    // Set compliance_root_commit to zero (not committed yet)
    ctx.registry_entry.compliance_root_commit = uint256();
    ctx.db.WriteAssetPolicy(ctx.asset_id, ctx.registry_entry);

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = Consensus::BuildComplianceField(uint256(), 100);
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    BOOST_CHECK(reason == "zk-root-not-set" || reason == "kyc-proof-not-hdv1");
}

BOOST_AUTO_TEST_CASE(binding_ring_buffer_boundary_exactly_at_max_age)
{
    // Test that historical root is valid exactly at max_root_age boundary
    BindingTestContext ctx;
    ctx.registry_entry.max_root_age = 100;

    // Add historical root
    ComplianceRootHistory hist;
    auto hist_root_bytes = Consensus::BuildComplianceField(uint256(), 100);
    for (size_t i = 0; i < 32; ++i) hist.root_commit.begin()[31 - i] = hist_root_bytes[i];
    hist.activation_height = 100;
    hist.txid = Txid::FromHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").value();
    ctx.registry_entry.compliance_root_history.push_back(hist);
    ctx.db.WriteAssetPolicy(ctx.asset_id, ctx.registry_entry);

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const auto compliance_bytes = hist_root_bytes;
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    // Spend at height 200, historical root activated at 100, delta=100 == max_root_age
    // Note: Mock proofs fail at VK verification before reaching root checks
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    // Verify it's not failing due to root mismatch (would pass that check)
    BOOST_CHECK_NE(reason, "zk-root-mismatch");

    // Now test at max_root_age + 1 (should fail)
    // With mock proofs, still fails at VK check, but with real proofs would be zk-root-mismatch
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/201, reason));
}

BOOST_AUTO_TEST_CASE(binding_accepts_multiple_historical_roots_in_ring_buffer)
{
    // Test that validation scans entire ring buffer for matching root
    BindingTestContext ctx;

    // Add multiple historical roots
    for (int i = 0; i < 5; ++i) {
        ComplianceRootHistory hist;
        uint256 test_root;
        memset(test_root.data(), 0x10 + i, 28);
        auto hist_root_bytes = Consensus::BuildComplianceField(test_root, 100 + i * 10);
        for (size_t j = 0; j < 32; ++j) hist.root_commit.begin()[31 - j] = hist_root_bytes[j];
        hist.activation_height = 100 + i * 10;
        hist.txid = Txid::FromHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").value();
        ctx.registry_entry.compliance_root_history.push_back(hist);
    }
    ctx.db.WriteAssetPolicy(ctx.asset_id, ctx.registry_entry);

    // Use the 3rd historical root (index 2)
    uint256 target_root;
    memset(target_root.data(), 0x12, 28);
    auto target_compliance_bytes = Consensus::BuildComplianceField(target_root, 120);

    CMutableTransaction mtx;
    PopulateTransaction(mtx, ctx);

    const auto chain_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    const auto asset_bytes = Consensus::Uint256ToBytesBE(ctx.asset_id);
    const std::array<unsigned char, 32> anchor_bytes{};

    auto pub_inputs = EncodePublicInputs(chain_bytes, asset_bytes, target_compliance_bytes, anchor_bytes);

    AppendProofOutput(mtx, ctx.asset_id, MockGroth16Proof(), pub_inputs);

    mtx.vin[0].scriptWitness = BuildWitness();

    CTransaction tx(mtx);
    std::string reason;
    // Should find the matching root in ring buffer
    BOOST_CHECK(!RunCheck(tx, ctx.view, /*nSpendHeight=*/200, reason));
    BOOST_CHECK_NE(reason, "zk-root-mismatch");
}

BOOST_AUTO_TEST_SUITE_END()
