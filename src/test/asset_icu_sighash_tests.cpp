// Tests for ICU signature hash enforcement in consensus and policy layers.

#include <boost/test/unit_test.hpp>

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <coins.h>
#include <serialize.h>
#include <txdb.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>

#include <assets/asset.h>

#include <script/script.h>
#include <script/interpreter.h>

#include <cstring>
#include <optional>
#include <vector>

namespace {

using AID = uint256;

[[maybe_unused]] std::vector<unsigned char> TLV(uint8_t type, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> out;
    out.push_back(type);
    if (payload.size() < 253) {
        out.push_back(static_cast<unsigned char>(payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        out.push_back(253);
        out.push_back(static_cast<unsigned char>(payload.size() & 0xFF));
        out.push_back(static_cast<unsigned char>((payload.size() >> 8) & 0xFF));
    } else {
        out.push_back(254);
        for (int i = 0; i < 4; ++i) {
            out.push_back(static_cast<unsigned char>((payload.size() >> (i * 8)) & 0xFF));
        }
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<unsigned char> MakeIssuerReg(const AID& id, uint32_t policy_bits, uint16_t allowed)
{
    return test_util::BuildV1IssuerReg(id, policy_bits, allowed);
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

struct TestContext {
    CCoinsViewDB db;
    CCoinsViewCache view;
    AID asset_id;
    COutPoint icu_prevout;
    CTxOut icu_coin;

    TestContext()
        : db({.path = "icu-sighash", .cache_bytes = 1 << 20, .memory_only = true}, {})
        , view(&db)
    {
        asset_id.SetNull();
        asset_id.begin()[0] = 0xAA;
        Txid txid;
        memset(const_cast<std::byte*>(txid.data()), 0x44, txid.size());
        icu_prevout = COutPoint(txid, 0);

        icu_coin = CTxOut(1000, CScript() << OP_TRUE);
        icu_coin.vExt = MakeIssuerReg(asset_id, /*policy_bits=*/assets::MINT_ALLOWED, assets::SPK_DEFAULT_ALLOWED);
        view.AddCoin(icu_prevout, Coin(icu_coin, /*height=*/5, /*coinbase=*/false), /*overwrite=*/false);
    }
};

bool RunCheck(const CTransaction& tx, CCoinsViewCache& view, std::string& reason)
{
    CAmount fee{0};
    TxValidationState state;
    if (!Consensus::CheckTxInputs(tx, state, view, /*height=*/200, fee)) {
        reason = state.GetRejectReason();
        return false;
    }
    return true;
}

CTransaction BuildIcuSpendTx(const COutPoint& prevout, const CTxOut& coin, const std::optional<std::vector<unsigned char>>& signature)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(prevout);
    if (signature.has_value()) {
        mtx.vin[0].scriptWitness.stack.push_back(*signature);
    }
    mtx.vout.push_back(coin);
    return CTransaction(mtx);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_icu_sighash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(icu_sighash_all_explicit)
{
    TestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x01, /*sighash=*/SIGHASH_ALL);
    CTransaction tx = BuildIcuSpendTx(ctx.icu_prevout, ctx.icu_coin, sig);
    std::string reason;
    BOOST_CHECK(RunCheck(tx, ctx.view, reason));
}

BOOST_AUTO_TEST_CASE(icu_sighash_default_taproot)
{
    TestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x02, /*sighash=*/std::nullopt);
    CTransaction tx = BuildIcuSpendTx(ctx.icu_prevout, ctx.icu_coin, sig);
    std::string reason;
    BOOST_CHECK(RunCheck(tx, ctx.view, reason));
}

BOOST_AUTO_TEST_CASE(icu_sighash_anyonecanpay_rejected)
{
    TestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x03, /*sighash=*/static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    CTransaction tx = BuildIcuSpendTx(ctx.icu_prevout, ctx.icu_coin, sig);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "icu-invalid-sighash");
}

BOOST_AUTO_TEST_CASE(icu_sighash_single_rejected)
{
    TestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x04, /*sighash=*/SIGHASH_SINGLE);
    CTransaction tx = BuildIcuSpendTx(ctx.icu_prevout, ctx.icu_coin, sig);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "icu-invalid-sighash");
}

BOOST_AUTO_TEST_CASE(icu_sighash_none_rejected)
{
    TestContext ctx;
    auto sig = MakeSchnorrSig(/*fill=*/0x05, /*sighash=*/SIGHASH_NONE);
    CTransaction tx = BuildIcuSpendTx(ctx.icu_prevout, ctx.icu_coin, sig);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "icu-invalid-sighash");
}

BOOST_AUTO_TEST_CASE(icu_missing_signature_rejected)
{
    TestContext ctx;
    CTransaction tx = BuildIcuSpendTx(ctx.icu_prevout, ctx.icu_coin, std::nullopt);
    std::string reason;
    BOOST_CHECK(!RunCheck(tx, ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "icu-missing-signature");
}

BOOST_AUTO_TEST_CASE(icu_ecdsa_sighash_all_accepted)
{
    TestContext ctx;
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.icu_prevout);
    mtx.vin[0].scriptSig << MakeDerSig(SIGHASH_ALL);
    mtx.vout.push_back(ctx.icu_coin);
    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason));
}

BOOST_AUTO_TEST_CASE(icu_ecdsa_anyonecanpay_rejected)
{
    TestContext ctx;
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ctx.icu_prevout);
    mtx.vin[0].scriptSig << MakeDerSig(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    mtx.vout.push_back(ctx.icu_coin);
    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "icu-invalid-sighash");
}

BOOST_AUTO_TEST_CASE(icu_taproot_annex_handled)
{
    TestContext ctx;
    std::vector<unsigned char> annex(64, 0x51);
    annex.front() = 0x50; // Annex marker
    auto sig = MakeSchnorrSig(0x07, std::nullopt);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(ctx.icu_prevout);
    mtx.vin[0].scriptWitness.stack.push_back(annex);
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vout.push_back(ctx.icu_coin);
    std::string reason;
    BOOST_CHECK(RunCheck(CTransaction(mtx), ctx.view, reason));
}

BOOST_AUTO_TEST_CASE(icu_multisig_mixed_sighash_rejected)
{
    TestContext ctx;
    CMutableTransaction mtx;
    mtx.vin.emplace_back(ctx.icu_prevout);
    auto good_sig = MakeSchnorrSig(0x08, SIGHASH_ALL);
    auto bad_sig = MakeSchnorrSig(0x09, static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    mtx.vin[0].scriptWitness.stack.push_back(good_sig);
    mtx.vin[0].scriptWitness.stack.push_back(bad_sig);
    mtx.vout.push_back(ctx.icu_coin);
    std::string reason;
    BOOST_CHECK(!RunCheck(CTransaction(mtx), ctx.view, reason));
    BOOST_CHECK_EQUAL(reason, "icu-invalid-sighash");
}

BOOST_AUTO_TEST_SUITE_END()
