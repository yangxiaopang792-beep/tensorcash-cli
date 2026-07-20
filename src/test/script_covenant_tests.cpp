// Copyright (c) 2024 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/test/unit_test.hpp>

#include <assets/asset.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <cstring>
#include <optional>
#include <vector>

namespace {

CScript MakeP2TRScript(unsigned char fill)
{
    std::vector<unsigned char> key(32, fill);
    return CScript() << OP_1 << key;
}

std::vector<unsigned char> MakeAssetTag(const uint256& asset_id, uint64_t amount)
{
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(40); // compact size for 32 + 8 bytes
    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
    unsigned char buf[8];
    WriteLE64(buf, amount);
    tlv.insert(tlv.end(), buf, buf + 8);
    return tlv;
}

std::vector<unsigned char> AmountLE(uint64_t amount)
{
    std::vector<unsigned char> buf(sizeof(uint64_t));
    WriteLE64(buf.data(), amount);
    return buf;
}

std::pair<bool, ScriptError> EvalNativeOpcode(const CTransaction& tx, const uint256& script_hash, uint64_t amount, SigVersion sigversion)
{
    CScript script;
    script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
    script << AmountLE(amount);
    script << OP_OUTPUTMATCH_NATIVE;

    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    ScriptError err = SCRIPT_ERR_OK;
    bool ok = EvalScript(stack, script, SCRIPT_VERIFY_TAPROOT, checker, sigversion, execdata, &err);
    return {ok, err};
}

std::pair<bool, ScriptError> EvalAssetOpcode(const CTransaction& tx, const uint256& script_hash, const uint256& asset_id, uint64_t amount, SigVersion sigversion)
{
    CScript script;
    script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
    script << std::vector<unsigned char>(asset_id.begin(), asset_id.end());
    script << AmountLE(amount);
    script << OP_OUTPUTMATCH_ASSET;

    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    ScriptError err = SCRIPT_ERR_OK;
    bool ok = EvalScript(stack, script, SCRIPT_VERIFY_TAPROOT, checker, sigversion, execdata, &err);
    return {ok, err};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(script_covenant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(outputmatches_native_success)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x02);
    mtx.vout.emplace_back(CAmount{1000}, spk);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk);
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/true, std::nullopt, /*amount=*/1000, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_asset_success)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x05);
    CTxOut out(CAmount{0}, spk);
    uint256 asset_id;
    std::memset(asset_id.data(), 0x11, asset_id.size());
    out.vExt = MakeAssetTag(asset_id, /*amount=*/5000);
    mtx.vout.emplace_back(out);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk);
    bool has_context = false;
    std::optional<uint256> asset_id_opt(asset_id);
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/false, asset_id_opt, /*amount=*/5000, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_native_mismatch)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x07);
    mtx.vout.emplace_back(CAmount{1500}, spk);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk);
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/true, std::nullopt, /*amount=*/999, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(!matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_native_rejects_asset)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x09);
    CTxOut out(CAmount{1000}, spk);
    uint256 asset_id;
    std::memset(asset_id.data(), 0x22, asset_id.size());
    out.vExt = MakeAssetTag(asset_id, /*amount=*/1000);
    mtx.vout.emplace_back(out);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk);
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/true, std::nullopt, /*amount=*/1000, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(!matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_asset_wrong_id)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x0A);
    CTxOut out(CAmount{0}, spk);
    uint256 asset_id;
    std::memset(asset_id.data(), 0x31, asset_id.size());
    out.vExt = MakeAssetTag(asset_id, /*amount=*/7000);
    mtx.vout.emplace_back(out);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk);
    uint256 wrong_id;
    std::memset(wrong_id.data(), 0x32, wrong_id.size());
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/false, std::optional<uint256>(wrong_id), /*amount=*/7000, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(!matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_asset_wrong_amount)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x0B);
    CTxOut out(CAmount{0}, spk);
    uint256 asset_id;
    std::memset(asset_id.data(), 0x41, asset_id.size());
    out.vExt = MakeAssetTag(asset_id, /*amount=*/8000);
    mtx.vout.emplace_back(out);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk);
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/false, std::optional<uint256>(asset_id), /*amount=*/7000, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(!matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_opreturn_never_matches)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript opret = CScript() << OP_RETURN << std::vector<unsigned char>(4, 0xAA);
    mtx.vout.emplace_back(CAmount{1000}, opret);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(opret);
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/true, std::nullopt, /*amount=*/1000, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(!matched);
}

BOOST_AUTO_TEST_CASE(outputmatches_multiple_outputs)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk1 = MakeP2TRScript(0x10);
    CScript spk2 = MakeP2TRScript(0x11);
    mtx.vout.emplace_back(CAmount{500}, spk1);
    mtx.vout.emplace_back(CAmount{700}, spk2);
    const CTransaction tx{mtx};

    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    uint256 script_hash = ComputeTapMatch(spk2);
    bool has_context = false;
    bool matched = OutputMatches(checker, script_hash, /*native_only=*/true, std::nullopt, /*amount=*/700, has_context);

    BOOST_CHECK(has_context);
    BOOST_CHECK(matched);
}

BOOST_AUTO_TEST_CASE(opcode_native_amount_zero_fails)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x12);
    mtx.vout.emplace_back(CAmount{1000}, spk);
    const CTransaction tx{mtx};

    auto [ok, err] = EvalNativeOpcode(tx, ComputeTapMatch(spk), /*amount=*/0, SigVersion::TAPSCRIPT);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_AMOUNT_OUT_OF_RANGE);
}

BOOST_AUTO_TEST_CASE(opcode_native_amount_overflow_fails)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x13);
    mtx.vout.emplace_back(CAmount{MAX_MONEY}, spk);
    const CTransaction tx{mtx};

    auto [ok, err] = EvalNativeOpcode(tx, ComputeTapMatch(spk), static_cast<uint64_t>(MAX_MONEY) + 1, SigVersion::TAPSCRIPT);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_AMOUNT_OUT_OF_RANGE);
}

BOOST_AUTO_TEST_CASE(opcode_native_requires_tapscript)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x14);
    mtx.vout.emplace_back(CAmount{1000}, spk);
    const CTransaction tx{mtx};

    auto [ok, err] = EvalNativeOpcode(tx, ComputeTapMatch(spk), /*amount=*/1000, SigVersion::WITNESS_V0);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_ONLY);
}

BOOST_AUTO_TEST_CASE(opcode_native_invalid_operand_size)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x15);
    mtx.vout.emplace_back(CAmount{1000}, spk);
    const CTransaction tx{mtx};

    uint256 script_hash = ComputeTapMatch(spk);
    CScript script;
    script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
    script << std::vector<unsigned char>(4, 0x01); // wrong size
    script << OP_OUTPUTMATCH_NATIVE;

    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    ScriptError err = SCRIPT_ERR_OK;
    bool ok = EvalScript(stack, script, SCRIPT_VERIFY_TAPROOT, checker, SigVersion::TAPSCRIPT, execdata, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_OPERAND_SIZE);
}

BOOST_AUTO_TEST_CASE(opcode_asset_amount_zero_fails)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x16);
    CTxOut out(CAmount{0}, spk);
    uint256 asset_id;
    std::memset(asset_id.data(), 0x51, asset_id.size());
    out.vExt = MakeAssetTag(asset_id, /*amount=*/1);
    mtx.vout.emplace_back(out);
    const CTransaction tx{mtx};

    auto [ok, err] = EvalAssetOpcode(tx, ComputeTapMatch(spk), asset_id, /*amount=*/0, SigVersion::TAPSCRIPT);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_AMOUNT_OUT_OF_RANGE);
}

BOOST_AUTO_TEST_CASE(opcode_asset_invalid_operand_size)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back();
    CScript spk = MakeP2TRScript(0x17);
    mtx.vout.emplace_back(CAmount{0}, spk);
    const CTransaction tx{mtx};

    uint256 script_hash = ComputeTapMatch(spk);
    CScript script;
    script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
    script << std::vector<unsigned char>(16, 0x01); // wrong asset id size
    script << AmountLE(5);
    script << OP_OUTPUTMATCH_ASSET;

    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    TransactionSignatureChecker checker(&tx, 0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    ScriptError err = SCRIPT_ERR_OK;
    bool ok = EvalScript(stack, script, SCRIPT_VERIFY_TAPROOT, checker, SigVersion::TAPSCRIPT, execdata, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_OPERAND_SIZE);
}

BOOST_AUTO_TEST_SUITE_END()
