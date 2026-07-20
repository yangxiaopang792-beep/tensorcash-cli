// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/util/setup_common.h>

#include <checkqueue.h>
#include <clientversion.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/transaction_utils.h>
#include <txdb.h>
#include <coins.h>
#include <script/interpreter.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <functional>
#include <map>
#include <string>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace util::hex_literals;
using util::SplitString;
using util::ToString;

typedef std::vector<unsigned char> valtype;

static CFeeRate g_dust{DUST_RELAY_TX_FEE};
static bool g_bare_multi{DEFAULT_PERMIT_BAREMULTISIG};

static std::map<std::string, unsigned int> mapFlagNames = {
    {std::string("P2SH"), (unsigned int)SCRIPT_VERIFY_P2SH},
    {std::string("STRICTENC"), (unsigned int)SCRIPT_VERIFY_STRICTENC},
    {std::string("DERSIG"), (unsigned int)SCRIPT_VERIFY_DERSIG},
    {std::string("LOW_S"), (unsigned int)SCRIPT_VERIFY_LOW_S},
    {std::string("SIGPUSHONLY"), (unsigned int)SCRIPT_VERIFY_SIGPUSHONLY},
    {std::string("MINIMALDATA"), (unsigned int)SCRIPT_VERIFY_MINIMALDATA},
    {std::string("NULLDUMMY"), (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {std::string("DISCOURAGE_UPGRADABLE_NOPS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {std::string("CLEANSTACK"), (unsigned int)SCRIPT_VERIFY_CLEANSTACK},
    {std::string("MINIMALIF"), (unsigned int)SCRIPT_VERIFY_MINIMALIF},
    {std::string("NULLFAIL"), (unsigned int)SCRIPT_VERIFY_NULLFAIL},
    {std::string("CHECKLOCKTIMEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {std::string("CHECKSEQUENCEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {std::string("WITNESS"), (unsigned int)SCRIPT_VERIFY_WITNESS},
    {std::string("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM},
    {std::string("WITNESS_PUBKEYTYPE"), (unsigned int)SCRIPT_VERIFY_WITNESS_PUBKEYTYPE},
    {std::string("CONST_SCRIPTCODE"), (unsigned int)SCRIPT_VERIFY_CONST_SCRIPTCODE},
    {std::string("TAPROOT"), (unsigned int)SCRIPT_VERIFY_TAPROOT},
    {std::string("TAPROOT_SCRIPT_ONLY"), (unsigned int)SCRIPT_VERIFY_TAPROOT_SCRIPT_ONLY},
    {std::string("DISCOURAGE_UPGRADABLE_PUBKEYTYPE"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE},
    {std::string("DISCOURAGE_OP_SUCCESS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS},
    {std::string("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION},
};

unsigned int ParseScriptFlags(std::string strFlags)
{
    unsigned int flags = SCRIPT_VERIFY_NONE;
    if (strFlags.empty() || strFlags == "NONE") return flags;

    std::vector<std::string> words = SplitString(strFlags, ',');
    for (const std::string& word : words)
    {
        if (!mapFlagNames.count(word))
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
        flags |= mapFlagNames[word];
    }
    return flags;
}

// Check that all flags in STANDARD_SCRIPT_VERIFY_FLAGS are present in mapFlagNames.
bool CheckMapFlagNames()
{
    unsigned int standard_flags_missing{STANDARD_SCRIPT_VERIFY_FLAGS};
    for (const auto& pair : mapFlagNames) {
        standard_flags_missing &= ~(pair.second);
    }
    return standard_flags_missing == 0;
}

std::string FormatScriptFlags(unsigned int flags)
{
    if (flags == SCRIPT_VERIFY_NONE) {
        return "";
    }
    std::string ret;
    std::map<std::string, unsigned int>::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first + ",";
        }
        it++;
    }
    return ret.substr(0, ret.size() - 1);
}

/*
* Check that the input scripts of a transaction are valid/invalid as expected.
*/
bool CheckTxScripts(const CTransaction& tx, const std::map<COutPoint, CScript>& map_prevout_scriptPubKeys,
    const std::map<COutPoint, int64_t>& map_prevout_values, unsigned int flags,
    const PrecomputedTransactionData& txdata, const std::string& strTest, bool expect_valid)
{
    bool tx_valid = true;
    ScriptError err = expect_valid ? SCRIPT_ERR_UNKNOWN_ERROR : SCRIPT_ERR_OK;
    for (unsigned int i = 0; i < tx.vin.size() && tx_valid; ++i) {
        const CTxIn input = tx.vin[i];
        const CAmount amount = map_prevout_values.count(input.prevout) ? map_prevout_values.at(input.prevout) : 0;
        try {
            tx_valid = VerifyScript(input.scriptSig, map_prevout_scriptPubKeys.at(input.prevout),
                &input.scriptWitness, flags, TransactionSignatureChecker(&tx, i, amount, txdata, MissingDataBehavior::ASSERT_FAIL), &err);
        } catch (...) {
            BOOST_ERROR("Bad test: " << strTest);
            return true; // The test format is bad and an error is thrown. Return true to silence further error.
        }
        if (expect_valid) {
            BOOST_CHECK_MESSAGE(tx_valid, strTest);
            BOOST_CHECK_MESSAGE((err == SCRIPT_ERR_OK), ScriptErrorString(err));
            err = SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    if (!expect_valid) {
        BOOST_CHECK_MESSAGE(!tx_valid, strTest);
        BOOST_CHECK_MESSAGE((err != SCRIPT_ERR_OK), ScriptErrorString(err));
    }
    return (tx_valid == expect_valid);
}

/*
 * Trim or fill flags to make the combination valid:
 * WITNESS must be used with P2SH
 * CLEANSTACK must be used WITNESS and P2SH
 */

unsigned int TrimFlags(unsigned int flags)
{
    // WITNESS requires P2SH
    if (!(flags & SCRIPT_VERIFY_P2SH)) flags &= ~(unsigned int)SCRIPT_VERIFY_WITNESS;

    // CLEANSTACK requires WITNESS (and transitively CLEANSTACK requires P2SH)
    if (!(flags & SCRIPT_VERIFY_WITNESS)) flags &= ~(unsigned int)SCRIPT_VERIFY_CLEANSTACK;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

unsigned int FillFlags(unsigned int flags)
{
    // CLEANSTACK implies WITNESS
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_WITNESS;

    // WITNESS implies P2SH (and transitively CLEANSTACK implies P2SH)
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

// Exclude each possible script verify flag from flags. Returns a set of these flag combinations
// that are valid and without duplicates. For example: if flags=1111 and the 4 possible flags are
// 0001, 0010, 0100, and 1000, this should return the set {0111, 1011, 1101, 1110}.
// Assumes that mapFlagNames contains all script verify flags.
std::set<unsigned int> ExcludeIndividualFlags(unsigned int flags)
{
    std::set<unsigned int> flags_combos;
    for (const auto& pair : mapFlagNames) {
        const unsigned int flags_excluding_one = TrimFlags(flags & ~(pair.second));
        if (flags != flags_excluding_one) {
            flags_combos.insert(flags_excluding_one);
        }
    }
    return flags_combos;
}

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tx_valid)
{
    BOOST_CHECK_MESSAGE(CheckMapFlagNames(), "mapFlagNames is missing a script verification flag");
    // Read tests from test/data/tx_valid.json
    UniValue tests = read_json(json_tests::tx_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue& input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4)
                {
                    fValid = false;
                    break;
                }
                COutPoint outpoint{Txid::FromHex(vinput[0].get_str()).value(), uint32_t(vinput[1].getInt<int>())};
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].getInt<int64_t>();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream(ParseHex(transaction));
            CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

            TxValidationState state;
            BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), strTest);
            BOOST_CHECK(state.IsValid());

            PrecomputedTransactionData txdata(tx);
            unsigned int verify_flags = ParseScriptFlags(test[2].get_str());

            // Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            if (~verify_flags != FillFlags(~verify_flags)) {
                BOOST_ERROR("Bad test flags: " << strTest);
            }

            BOOST_CHECK_MESSAGE(CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, ~verify_flags, txdata, strTest, /*expect_valid=*/true),
                                "Tx unexpectedly failed: " << strTest);

            // Backwards compatibility of script verification flags: Removing any flag(s) should not invalidate a valid transaction
            for (const auto& [name, flag] : mapFlagNames) {
                // Removing individual flags
                unsigned int flags = TrimFlags(~(verify_flags | flag));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Tx unexpectedly failed with flag " << name << " unset: " << strTest);
                }
                // Removing random combinations of flags
                flags = TrimFlags(~(verify_flags | (unsigned int)m_rng.randbits(mapFlagNames.size())));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Tx unexpectedly failed with random flags " << ToString(flags) << ": " << strTest);
                }
            }

            // Check that flags are maximal: transaction should fail if any unset flags are set.
            for (auto flags_excluding_one : ExcludeIndividualFlags(verify_flags)) {
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, ~flags_excluding_one, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Too many flags unset: " << strTest);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_vext_unknown_flags_and_malformed)
{
    // Create a tx with vExt and encode, then tamper with flags to include unknown bits
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = 0;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid{}, COutPoint::NULL_INDEX);
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    CScript spk = CScript() << OP_1;
    mtx.vout.emplace_back(CAmount{1000}, spk);
    mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x00u};
    std::string hex = EncodeHexTx(CTransaction(mtx));
    std::vector<unsigned char> bytes = ParseHex(hex);
    BOOST_REQUIRE(bytes.size() > 6);
    // bytes[4] = marker, bytes[5] = flags. Set an unknown flag bit 0x04 in addition to 0x02
    bytes[5] |= 0x04;
    DataStream bad(bytes);
    BOOST_CHECK_THROW({ CTransaction tx_bad(deserialize, TX_WITH_WITNESS, bad); }, std::ios_base::failure);

    // Malformed vExt: set ext size larger than actual payload
    // Find the first ext size varint and bump it
    // Roughly skip: 4 bytes version, 1 marker, 1 flags, vin vec, then vout vec count, then first out: nValue(8), scriptPubKey
    // This is a heuristic for this synthetic tx (one input, one output, spk = OP_1)
    // Move pointer to after version+marker+flags
    bytes = ParseHex(hex);
    size_t pos = 6; // after version(4), marker, flags
    // vin: compact size 1, then coinbase-like input with empty scriptSig length 1, so skip minimally
    // For robust check, just search for the first occurrence of 0x01 0x01 (varint=1 then OP_1 script len)
    // Then step past vout count (should be 0x01), nValue (8), and scriptPubKey (varint+1 byte)
    while (pos + 1 < bytes.size() && !(bytes[pos] == 0x01 && bytes[pos+1] == 0x01)) pos++;
    // Now pos at script len=1; advance past scriptPubKey (len byte + 1 byte)
    pos += 2;
    // At this point, the next byte should be the varint for ext size (currently 0x02 is set so ext sizes exist)
    if (pos < bytes.size()) {
        bytes[pos] = 0x05; // claim ext size 5 but only 2 bytes exist
        DataStream malformed(bytes);
        BOOST_CHECK_THROW({ CTransaction tx_bad2(deserialize, TX_WITH_WITNESS, malformed); }, std::exception);
    }
}

BOOST_AUTO_TEST_CASE(tx_vext_marker_flags_matrix_and_empty_ext)
{
    auto build_tx = [](bool with_witness, bool with_ext)->CTransaction {
        CMutableTransaction mtx;
        mtx.version = CTransaction::CURRENT_VERSION;
        mtx.nLockTime = 0;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(Txid{}, COutPoint::NULL_INDEX);
        mtx.vin[0].scriptSig = CScript() << OP_0;
        mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        if (with_witness) {
            mtx.vin[0].scriptWitness.stack = {std::vector<unsigned char>{}};
        }
        CScript spk = CScript() << OP_1;
        mtx.vout.emplace_back(CAmount{1000}, spk);
        mtx.vout.emplace_back(CAmount{2000}, spk);
        if (with_ext) {
            mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x00u};
            // Second output intentionally empty vExt
            mtx.vout[1].vExt.clear();
        }
        return CTransaction(mtx);
    };

    // Case 0x00: no witness, no ext => no marker/flags
    {
        auto tx = build_tx(false, false);
        auto bytes = ParseHex(EncodeHexTx(tx));
        BOOST_REQUIRE(bytes.size() > 4);
        BOOST_CHECK(bytes[4] != 0x00); // vin CompactSize, not marker
    }
    // Case 0x01: witness only
    {
        auto tx = build_tx(true, false);
        auto bytes = ParseHex(EncodeHexTx(tx));
        BOOST_REQUIRE(bytes.size() > 6);
        BOOST_CHECK_EQUAL(bytes[4], 0x00);
        BOOST_CHECK_EQUAL(bytes[5] & 0x01, 0x01);
        BOOST_CHECK_EQUAL(bytes[5] & 0x02, 0x00);
    }
    // Case 0x02: outext only
    {
        auto tx = build_tx(false, true);
        auto bytes = ParseHex(EncodeHexTx(tx));
        BOOST_REQUIRE(bytes.size() > 6);
        BOOST_CHECK_EQUAL(bytes[4], 0x00);
        BOOST_CHECK_EQUAL(bytes[5] & 0x01, 0x00);
        BOOST_CHECK_EQUAL(bytes[5] & 0x02, 0x02);
        // Decode and verify second vout has empty vExt
        UniValue u(UniValue::VOBJ);
        TxToUniv(tx, /*block_hash=*/uint256{}, u, /*include_hex=*/false);
        const auto& vout = u.find_value("vout");
        BOOST_REQUIRE(vout.isArray());
        const auto& v1 = vout[1];
        BOOST_REQUIRE(v1.isObject());
        BOOST_CHECK(v1.find_value("outext").isNull());
    }
    // Case 0x03: both
    {
        auto tx = build_tx(true, true);
        auto bytes = ParseHex(EncodeHexTx(tx));
        BOOST_REQUIRE(bytes.size() > 6);
        BOOST_CHECK_EQUAL(bytes[4], 0x00);
        BOOST_CHECK_EQUAL(bytes[5] & 0x01, 0x01);
        BOOST_CHECK_EQUAL(bytes[5] & 0x02, 0x02);
    }
}

BOOST_AUTO_TEST_CASE(coin_txoutcompression_vext_roundtrip)
{
    // Verify that Coin serialization via TxOutCompression round-trips vExt
    CTxOut out;
    out.nValue = 1234;
    out.scriptPubKey = CScript() << OP_1;
    out.vExt = std::vector<unsigned char>{0x01u, 0x00u, 0xAAu};

    Coin c1(out, /*height=*/42, /*coinbase=*/false);

    DataStream ss;
    c1.Serialize(ss);

    Coin c2;
    c2.Unserialize(ss);

    BOOST_CHECK_EQUAL(c2.nHeight, 42);
    BOOST_CHECK_EQUAL(c2.fCoinBase, false);
    BOOST_CHECK_EQUAL(c2.out.nValue, 1234);
    BOOST_CHECK(c2.out.scriptPubKey == (CScript() << OP_1));
    BOOST_CHECK(c2.out.vExt == out.vExt);
}

BOOST_AUTO_TEST_CASE(coin_vext_size_bounds)
{
    // Craft a compressed TxOut with ext size exceeding bound and ensure unser fails
    CTxOut out;
    out.nValue = 1;
    out.scriptPubKey = CScript();

    DataStream ss;
    // Serialize amount+script in compressed form
    ss << Using<AmountCompression>(out.nValue);
    ss << Using<ScriptCompression>(out.scriptPubKey);
    // Write oversized ext varint: MAX+1
    const size_t too_big = MAX_OUEXT_SIZE_PER_OUTPUT + 1;
    WriteCompactSize(ss, too_big);
    // Do not write any payload

    // Now try to unserialize using TxOutCompression
    CTxOut dst;
    auto unser = Using<TxOutCompression>(dst);
    BOOST_CHECK_THROW({ ss >> unser; }, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(coin_vext_database_persistence)
{
    // Memory-only coins DB round-trip using CCoinsViewDB and CCoinsViewCache
    CCoinsViewDB db_base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache cache(&db_base);

    // Add multiple coins with various vExt sizes
    auto make_txid = [](uint32_t x){
        uint256 u; // little helper
        // just set first 4 bytes
        unsigned char* p = u.begin();
        p[0] = x & 0xFF; p[1] = (x>>8)&0xFF; p[2] = (x>>16)&0xFF; p[3] = (x>>24)&0xFF;
        return Txid::FromUint256(u);
    };

    CScript spk = CScript() << OP_1;
    // Coin A: empty vExt
    {
        CTxOut out(1000, spk);
        out.vExt.clear();
        cache.AddCoin(COutPoint(make_txid(1), 0), Coin(out, /*height=*/10, /*coinbase=*/false), false);
    }
    // Coin B: small vExt
    {
        CTxOut out(2000, spk);
        out.vExt = std::vector<unsigned char>{0x01u, 0x00u};
        cache.AddCoin(COutPoint(make_txid(2), 0), Coin(out, /*height=*/11, /*coinbase=*/false), false);
    }
    // Coin C: max-bound vExt
    {
        CTxOut out(3000, spk);
        out.vExt.resize(MAX_OUEXT_SIZE_PER_OUTPUT, 0xAB);
        cache.AddCoin(COutPoint(make_txid(3), 0), Coin(out, /*height=*/12, /*coinbase=*/false), false);
    }

    // Flush with a non-null block hash (required by BatchWrite)
    uint256 dummy_hash = uint256::ONE;
    cache.SetBestBlock(dummy_hash);
    BOOST_CHECK(cache.Flush());

    // Read back and verify vExt round-trips from DB
    auto check_coin = [&](uint32_t id, size_t expect_ext){
        auto c = db_base.GetCoin(COutPoint(make_txid(id), 0));
        BOOST_REQUIRE(c.has_value());
        BOOST_CHECK_EQUAL(c->out.vExt.size(), expect_ext);
    };
    check_coin(1, 0);
    check_coin(2, 2);
    check_coin(3, MAX_OUEXT_SIZE_PER_OUTPUT);
}

BOOST_AUTO_TEST_CASE(tx_vext_total_ext_size_limit)
{
    // Build a tx whose total vExt size exceeds MAX_OUEXT_BYTES_PER_TX; deserialization must fail
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = 0;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid{}, COutPoint::NULL_INDEX);
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    // Create 9 outputs, each with vExt at the per-output max; total exceeds 128 KiB
    for (int i = 0; i < 9; ++i) {
        CTxOut out(CAmount{1000 + i}, CScript() << OP_1);
        out.vExt.resize(MAX_OUEXT_SIZE_PER_OUTPUT, 0xCD);
        mtx.vout.push_back(std::move(out));
    }
    // Serialize to hex
    std::string hex = EncodeHexTx(CTransaction(mtx));
    // Attempt to deserialize; should throw on total ext size limit
    DataStream ds(ParseHex(hex));
    BOOST_CHECK_THROW({ CTransaction tx_bad(deserialize, TX_WITH_WITNESS, ds); }, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(bip143_sighash_single_binds_vext)
{
    // Construct a segwit v0 tx with two outputs and witness, compute BIP143 SIGHASH_SINGLE
    // Verify that changing vExt of the output at index nIn changes the sighash,
    // and changing vExt of a different output does not.
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = 0;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid{}, 0);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    // Mark as witness spend to activate BIP143 path
    mtx.vin[0].scriptWitness.stack = {std::vector<unsigned char>{0x00}};

    // Two outputs
    CScript spk = CScript() << OP_1;
    mtx.vout.emplace_back(CAmount{1000}, spk);
    mtx.vout.emplace_back(CAmount{2000}, spk);
    // vExt on both, small TLV-like payloads
    mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x01u, 0xAAu};
    mtx.vout[1].vExt = std::vector<unsigned char>{0x01u, 0x01u, 0xBBu};

    CTransaction tx1(mtx);
    // Prepare PrecomputedTransactionData with spent outputs (required for BIP143)
    std::vector<CTxOut> spent(1);
    spent[0].nValue = 5000;
    spent[0].scriptPubKey = CScript() << OP_TRUE; // arbitrary
    PrecomputedTransactionData pre1;
    pre1.Init(tx1, std::move(spent), /*force=*/true);
    CAmount amount = 5000;
    CScript scriptCode = CScript() << OP_TRUE;
    uint256 h1 = SignatureHash(scriptCode, tx1, /*nIn=*/0, SIGHASH_SINGLE, amount, SigVersion::WITNESS_V0, &pre1);

    // Change vExt of output 0 (same index as nIn)
    mtx.vout[0].vExt[2] ^= 0xFF;
    CTransaction tx2(mtx);
    std::vector<CTxOut> spent2(1);
    spent2[0].nValue = 5000;
    spent2[0].scriptPubKey = CScript() << OP_TRUE;
    PrecomputedTransactionData pre2;
    pre2.Init(tx2, std::move(spent2), /*force=*/true);
    uint256 h2 = SignatureHash(scriptCode, tx2, 0, SIGHASH_SINGLE, amount, SigVersion::WITNESS_V0, &pre2);
    BOOST_CHECK(h1 != h2);

    // Change vExt of output 1 only; SIGHASH_SINGLE for nIn=0 should not change
    mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x01u, 0xAAu}; // restore
    mtx.vout[1].vExt[2] ^= 0xFF;
    CTransaction tx3(mtx);
    std::vector<CTxOut> spent3(1);
    spent3[0].nValue = 5000;
    spent3[0].scriptPubKey = CScript() << OP_TRUE;
    PrecomputedTransactionData pre3;
    pre3.Init(tx3, std::move(spent3), /*force=*/true);
    uint256 h3 = SignatureHash(scriptCode, tx3, 0, SIGHASH_SINGLE, amount, SigVersion::WITNESS_V0, &pre3);
    BOOST_CHECK(h1 == h3);
}

BOOST_AUTO_TEST_CASE(taproot_sighash_single_binds_vext)
{
    // Build a transaction with one Taproot input and two outputs, both with vExt.
    // Verify that Taproot SIGHASH_SINGLE binds vExt of the output at index nIn,
    // and is insensitive to vExt changes on other outputs.
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = 0;

    // One input spending a fake P2TR UTXO (scriptPubKey = OP_1 <32-bytes>)
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid{}, 0);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;

    // Two outputs with small TLV-like payloads
    CScript spk = CScript() << OP_1; // Any script; witness binding only cares about outputs serialization
    mtx.vout.emplace_back(CAmount{1000}, spk);
    mtx.vout.emplace_back(CAmount{2000}, spk);
    mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x01u, 0xAAu};
    mtx.vout[1].vExt = std::vector<unsigned char>{0x01u, 0x01u, 0xBBu};

    CTransaction tx(mtx);

    // Construct a Taproot prevout to satisfy BIP341 precomputation
    CScript spk_p2tr = CScript() << OP_1 << std::vector<unsigned char>(32, 0x01);
    std::vector<CTxOut> spent(1);
    spent[0].nValue = 5000;
    spent[0].scriptPubKey = spk_p2tr;

    PrecomputedTransactionData pre;
    pre.Init(tx, std::move(spent), /*force=*/true);

    // Prepare execution data (no annex)
    ScriptExecutionData sed;
    sed.m_annex_init = true;
    sed.m_annex_present = false;

    // Compute SIGHASH_SINGLE for input 0 (Taproot)
    uint256 h1, h2, h3;
    BOOST_CHECK(SignatureHashSchnorr(h1, sed, tx, /*nIn=*/0, SIGHASH_SINGLE, SigVersion::TAPROOT, pre, MissingDataBehavior::FAIL));

    // Mutate vExt of output 0 (same index as nIn) and recompute
    // Reset cached single-output hash in execution data to reflect tx mutation
    sed.m_output_hash.reset();
    mtx.vout[0].vExt[2] ^= 0xFF;
    CTransaction tx2(mtx);
    PrecomputedTransactionData pre2; pre2.Init(tx2, std::vector<CTxOut>{CTxOut{5000, spk_p2tr}}, /*force=*/true);
    BOOST_CHECK(SignatureHashSchnorr(h2, sed, tx2, 0, SIGHASH_SINGLE, SigVersion::TAPROOT, pre2, MissingDataBehavior::FAIL));
    BOOST_CHECK(h1 != h2);

    // Restore and mutate vExt of output 1 only; SIGHASH_SINGLE for nIn=0 should not change
    sed.m_output_hash.reset();
    mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x01u, 0xAAu};
    mtx.vout[1].vExt[2] ^= 0xFF;
    CTransaction tx3(mtx);
    PrecomputedTransactionData pre3; pre3.Init(tx3, std::vector<CTxOut>{CTxOut{5000, spk_p2tr}}, /*force=*/true);
    BOOST_CHECK(SignatureHashSchnorr(h3, sed, tx3, 0, SIGHASH_SINGLE, SigVersion::TAPROOT, pre3, MissingDataBehavior::FAIL));
    BOOST_CHECK(h1 == h3);
}




BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid.json
    UniValue tests = read_json(json_tests::tx_invalid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue& input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4)
                {
                    fValid = false;
                    break;
                }
                COutPoint outpoint{Txid::FromHex(vinput[0].get_str()).value(), uint32_t(vinput[1].getInt<int>())};
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].getInt<int64_t>();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream(ParseHex(transaction));
            CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

            TxValidationState state;
            if (!CheckTransaction(tx, state) || state.IsInvalid()) {
                BOOST_CHECK_MESSAGE(test[2].get_str() == "BADTX", strTest);
                continue;
            }

            PrecomputedTransactionData txdata(tx);
            unsigned int verify_flags = ParseScriptFlags(test[2].get_str());

            // Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            if (verify_flags != FillFlags(verify_flags)) {
                BOOST_ERROR("Bad test flags: " << strTest);
            }

            // Not using FillFlags() in the main test, in order to detect invalid verifyFlags combination
            BOOST_CHECK_MESSAGE(CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, verify_flags, txdata, strTest, /*expect_valid=*/false),
                                "Tx unexpectedly passed: " << strTest);

            // Backwards compatibility of script verification flags: Adding any flag(s) should not validate an invalid transaction
            for (const auto& [name, flag] : mapFlagNames) {
                unsigned int flags = FillFlags(verify_flags | flag);
                // Adding individual flags
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Tx unexpectedly passed with flag " << name << " set: " << strTest);
                }
                // Adding random combinations of flags
                flags = FillFlags(verify_flags | (unsigned int)m_rng.randbits(mapFlagNames.size()));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Tx unexpectedly passed with random flags " << name << ": " << strTest);
                }
            }

            // Check that flags are minimal: transaction should succeed if any set flags are unset.
            for (auto flags_excluding_one : ExcludeIndividualFlags(verify_flags)) {
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags_excluding_one, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Too many flags set: " << strTest);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_vext_hash_and_serialization)
{
    // Build a simple transaction with one input and two outputs,
    // add per-output extension bytes to one output and verify that
    // (1) txid and wtxid change when vExt changes, and
    // (2) TX_WITH_WITNESS serialization contains marker 0x00 and flags 0x02,
    // (3) decoder includes outext hex when present.

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = 0;
    // coinbase-like input is fine for serialization/hash tests
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid{}, COutPoint::NULL_INDEX);
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;

    // Two outputs
    CScript spk = CScript() << OP_1;
    mtx.vout.emplace_back(CAmount{1000}, spk);
    mtx.vout.emplace_back(CAmount{2000}, spk);

    // Add extension to first output
    mtx.vout[0].vExt = std::vector<unsigned char>{0x01u, 0x00u};

    CTransaction tx1(mtx);
    const auto h1 = tx1.GetHash();
    const auto w1 = tx1.GetWitnessHash();

    // Mutate extension
    mtx.vout[0].vExt[1] = 0xFFu;
    CTransaction tx2(mtx);
    const auto h2 = tx2.GetHash();
    const auto w2 = tx2.GetWitnessHash();

    BOOST_CHECK(h1 != h2);
    BOOST_CHECK(w1 != w2);

    // Ensure TX_WITH_WITNESS serialization has marker 0x00 and flags 0x02
    std::string hex = EncodeHexTx(tx2);
    std::vector<unsigned char> bytes = ParseHex(hex);
    BOOST_REQUIRE(bytes.size() > 6);
    // version is 4 bytes LE, then marker and flags
    BOOST_CHECK_EQUAL(bytes[4], 0x00);
    BOOST_CHECK_EQUAL(bytes[5] & 0x02, 0x02);

    // Check decoder exposes outext hex when present
    UniValue entry(UniValue::VOBJ);
    TxToUniv(tx2, /*block_hash=*/uint256{}, entry, /*include_hex=*/false);
    const UniValue& vout = entry.find_value("vout");
    BOOST_REQUIRE(vout.isArray());
    const UniValue& v0 = vout[0];
    BOOST_REQUIRE(v0.isObject());
    const UniValue& ext0 = v0.find_value("outext");
    BOOST_CHECK(ext0.isStr());
    BOOST_CHECK(!ext0.get_str().empty());
}

BOOST_AUTO_TEST_CASE(tx_no_inputs)
{
    CMutableTransaction empty;

    TxValidationState state;
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(empty), state), "Transaction with no inputs should be invalid.");
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-vin-empty");
}

BOOST_AUTO_TEST_CASE(tx_oversized)
{
    auto createTransaction =[](size_t payloadSize) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.emplace_back(1, CScript() << OP_RETURN << std::vector<unsigned char>(payloadSize));
        return CTransaction(tx);
    };
    const auto maxTransactionSize = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    const auto oversizedTransactionBaseSize = ::GetSerializeSize(TX_NO_WITNESS(createTransaction(maxTransactionSize))) - maxTransactionSize;

    auto maxPayloadSize = maxTransactionSize - oversizedTransactionBaseSize;
    {
        TxValidationState state;
        CheckTransaction(createTransaction(maxPayloadSize), state);
        BOOST_CHECK(state.GetRejectReason() != "bad-txns-oversize");
    }

    maxPayloadSize += 1;
    {
        TxValidationState state;
        BOOST_CHECK_MESSAGE(!CheckTransaction(createTransaction(maxPayloadSize), state), "Oversized transaction should be invalid");
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-oversize");
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    // Random real transaction (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    DataStream stream(vch);
    CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction(tx), state) && state.IsValid(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(tx), state) || !state.IsValid(), "Transaction with duplicate txins should be invalid.");
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins));
}

static void CreateCreditAndSpend(const FillableSigningProvider& keystore, const CScript& outscript, CTransactionRef& output, CMutableTransaction& input, bool success = true)
{
    CMutableTransaction outputm;
    outputm.version = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = outscript;
    DataStream ssout;
    ssout << TX_WITH_WITNESS(outputm);
    ssout >> TX_WITH_WITNESS(output);
    assert(output->vin.size() == 1);
    assert(output->vin[0] == outputm.vin[0]);
    assert(output->vout.size() == 1);
    assert(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.version = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout.hash = output->GetHash();
    inputm.vin[0].prevout.n = 0;
    inputm.vout.resize(1);
    inputm.vout[0].nValue = 1;
    inputm.vout[0].scriptPubKey = CScript();
    SignatureData empty;
    bool ret = SignSignature(keystore, *output, inputm, 0, SIGHASH_ALL, empty);
    assert(ret == success);
    DataStream ssin;
    ssin << TX_WITH_WITNESS(inputm);
    ssin >> TX_WITH_WITNESS(input);
    assert(input.vin.size() == 1);
    assert(input.vin[0] == inputm.vin[0]);
    assert(input.vout.size() == 1);
    assert(input.vout[0] == inputm.vout[0]);
    assert(input.vin[0].scriptWitness.stack == inputm.vin[0].scriptWitness.stack);
}

static void CheckWithFlag(const CTransactionRef& output, const CMutableTransaction& input, uint32_t flags, bool success)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output->vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output->vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &error);
    assert(ret == success);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

static void ReplaceRedeemScript(CScript& script, const CScript& redeemScript)
{
    std::vector<valtype> stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
    assert(stack.size() > 0);
    stack.back() = std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_witness_transaction)
{
    CMutableTransaction mtx;
    mtx.version = 1;

    CKey key = GenerateRandomKey(); // Need to use compressed keys in segwit or the signing will fail
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKeyPubKey(key, key.GetPubKey()));
    CKeyID hash = key.GetPubKey().GetID();
    CScript scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(hash.begin(), hash.end());

    std::vector<int> sigHashes;
    sigHashes.push_back(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_NONE);
    sigHashes.push_back(SIGHASH_SINGLE);
    sigHashes.push_back(SIGHASH_ALL);

    // create a big transaction of 4500 inputs signed by the same key
    for(uint32_t ij = 0; ij < 4500; ij++) {
        uint32_t i = mtx.vin.size();
        COutPoint outpoint(Txid::FromHex("0000000000000000000000000000000000000000000000000000000000000100").value(), i);

        mtx.vin.resize(mtx.vin.size() + 1);
        mtx.vin[i].prevout = outpoint;
        mtx.vin[i].scriptSig = CScript();

        mtx.vout.resize(mtx.vout.size() + 1);
        mtx.vout[i].nValue = 1000;
        mtx.vout[i].scriptPubKey = CScript() << OP_1;
    }

    // sign all inputs
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        SignatureData empty;
        bool hashSigned = SignSignature(keystore, scriptPubKey, mtx, i, 1000, sigHashes.at(i % sigHashes.size()), empty);
        assert(hashSigned);
    }

    DataStream ssout;
    ssout << TX_WITH_WITNESS(mtx);
    CTransaction tx(deserialize, TX_WITH_WITNESS, ssout);

    // check all inputs concurrently, with the cache
    PrecomputedTransactionData txdata(tx);
    CCheckQueue<CScriptCheck> scriptcheckqueue(/*batch_size=*/128, /*worker_threads_num=*/20);
    CCheckQueueControl<CScriptCheck> control(&scriptcheckqueue);

    std::vector<Coin> coins;
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        Coin coin;
        coin.nHeight = 1;
        coin.fCoinBase = false;
        coin.out.nValue = 1000;
        coin.out.scriptPubKey = scriptPubKey;
        coins.emplace_back(std::move(coin));
    }

    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        std::vector<CScriptCheck> vChecks;
        vChecks.emplace_back(coins[tx.vin[i].prevout.n].out, tx, signature_cache, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false, &txdata);
        control.Add(std::move(vChecks));
    }

    bool controlCheck = !control.Complete().has_value();
    assert(controlCheck);
}

SignatureData CombineSignatures(const CMutableTransaction& input1, const CMutableTransaction& input2, const CTransactionRef tx)
{
    SignatureData sigdata;
    sigdata = DataFromTransaction(input1, 0, tx->vout[0]);
    sigdata.MergeSignatureData(DataFromTransaction(input2, 0, tx->vout[0]));
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(input1, 0, tx->vout[0].nValue, SIGHASH_ALL), tx->vout[0].scriptPubKey, sigdata);
    return sigdata;
}

BOOST_AUTO_TEST_CASE(test_witness)
{
    FillableSigningProvider keystore, keystore2;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey();
    CKey key3 = GenerateRandomKey();
    CKey key1L = GenerateRandomKey(/*compressed=*/false);
    CKey key2L = GenerateRandomKey(/*compressed=*/false);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    CPubKey pubkey3 = key3.GetPubKey();
    CPubKey pubkey1L = key1L.GetPubKey();
    CPubKey pubkey2L = key2L.GetPubKey();
    BOOST_CHECK(keystore.AddKeyPubKey(key1, pubkey1));
    BOOST_CHECK(keystore.AddKeyPubKey(key2, pubkey2));
    BOOST_CHECK(keystore.AddKeyPubKey(key1L, pubkey1L));
    BOOST_CHECK(keystore.AddKeyPubKey(key2L, pubkey2L));
    CScript scriptPubkey1, scriptPubkey2, scriptPubkey1L, scriptPubkey2L, scriptMulti;
    scriptPubkey1 << ToByteVector(pubkey1) << OP_CHECKSIG;
    scriptPubkey2 << ToByteVector(pubkey2) << OP_CHECKSIG;
    scriptPubkey1L << ToByteVector(pubkey1L) << OP_CHECKSIG;
    scriptPubkey2L << ToByteVector(pubkey2L) << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1L));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2L));
    BOOST_CHECK(keystore.AddCScript(scriptMulti));
    CScript destination_script_1, destination_script_2, destination_script_1L, destination_script_2L, destination_script_multi;
    destination_script_1 = GetScriptForDestination(WitnessV0KeyHash(pubkey1));
    destination_script_2 = GetScriptForDestination(WitnessV0KeyHash(pubkey2));
    destination_script_1L = GetScriptForDestination(WitnessV0KeyHash(pubkey1L));
    destination_script_2L = GetScriptForDestination(WitnessV0KeyHash(pubkey2L));
    destination_script_multi = GetScriptForDestination(WitnessV0ScriptHash(scriptMulti));
    BOOST_CHECK(keystore.AddCScript(destination_script_1));
    BOOST_CHECK(keystore.AddCScript(destination_script_2));
    BOOST_CHECK(keystore.AddCScript(destination_script_1L));
    BOOST_CHECK(keystore.AddCScript(destination_script_2L));
    BOOST_CHECK(keystore.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddCScript(scriptMulti));
    BOOST_CHECK(keystore2.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddKeyPubKey(key3, pubkey3));

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;

    // Normal pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Witness pay-to-compressed-pubkey (v0).
    CreateCreditAndSpend(keystore, destination_script_1, output1, input1);
    CreateCreditAndSpend(keystore, destination_script_2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH witness pay-to-compressed-pubkey (v0).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, destination_script_1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1L, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2L, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1L)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2L)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1L);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Signing disabled for witness pay-to-uncompressed-pubkey (v1).
    CreateCreditAndSpend(keystore, destination_script_1L, output1, input1, false);
    CreateCreditAndSpend(keystore, destination_script_2L, output2, input2, false);

    // Signing disabled for P2SH witness pay-to-uncompressed-pubkey (v1).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1L)), output1, input1, false);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2L)), output2, input2, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptMulti)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(scriptMulti)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // Witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, destination_script_multi, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, destination_script_multi, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_multi)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(destination_script_multi)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90*CENT;
    CKey key = GenerateRandomKey();
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    constexpr auto CheckIsStandard = [](const auto& t) {
        std::string reason;
        BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi, g_dust, reason));
        BOOST_CHECK(reason.empty());
    };
    constexpr auto CheckIsNotStandard = [](const auto& t, const std::string& reason_in) {
        std::string reason;
        BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi, g_dust, reason));
        BOOST_CHECK_EQUAL(reason_in, reason);
    };

    CheckIsStandard(t);

    // Check dust with default relay fee:
    CAmount nDustThreshold = 182 * g_dust.GetFeePerK() / 1000;
    BOOST_CHECK_EQUAL(nDustThreshold, 546);

    // Add dust outputs up to allowed maximum, still standard!
    for (size_t i{0}; i < MAX_DUST_OUTPUTS_PER_TX; ++i) {
        t.vout.emplace_back(0, t.vout[0].scriptPubKey);
        CheckIsStandard(t);
    }

    // dust:
    t.vout[0].nValue = nDustThreshold - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    CheckIsStandard(t);

    // Disallowed version
    t.version = std::numeric_limits<uint32_t>::max();
    CheckIsNotStandard(t, "version");

    t.version = 0;
    CheckIsNotStandard(t, "version");

    t.version = TX_MAX_STANDARD_VERSION + 1;
    CheckIsNotStandard(t, "version");

    // Allowed version
    t.version = 1;
    CheckIsStandard(t);

    t.version = 2;
    CheckIsStandard(t);

    // Check dust with odd relay fee to verify rounding:
    // nDustThreshold = 182 * 3702 / 1000
    g_dust = CFeeRate(3702);
    // dust:
    t.vout[0].nValue = 674 - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = 674;
    CheckIsStandard(t);
    g_dust = CFeeRate{DUST_RELAY_TX_FEE};

    t.vout[0].scriptPubKey = CScript() << OP_1;
    CheckIsNotStandard(t, "scriptpubkey");

    // MAX_OP_RETURN_RELAY-byte TxoutType::NULL_DATA (standard)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    CheckIsStandard(t);

    // MAX_OP_RETURN_RELAY+1-byte TxoutType::NULL_DATA (non-standard)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3800"_hex;
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    CheckIsNotStandard(t, "scriptpubkey");

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ""_hex;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "00"_hex << "01"_hex;
    CheckIsStandard(t);
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0 << "01"_hex << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << 0 << "01"_hex << 2 << "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex;
    CheckIsStandard(t);

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    CheckIsNotStandard(t, "scriptpubkey");

    // TxoutType::NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    // Only one TxoutType::NULL_DATA permitted in all cases
    t.vout.resize(2);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[0].nValue = 0;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].nValue = 0;
    CheckIsNotStandard(t, "multi-op-return");

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsNotStandard(t, "multi-op-return");

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsNotStandard(t, "multi-op-return");

    // Check large scriptSig (non-standard if size is >1650 bytes)
    t.vout.resize(1);
    t.vout[0].nValue = MAX_MONEY;
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    // OP_PUSHDATA2 with len (3 bytes) + data (1647 bytes) = 1650 bytes
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1647, 0); // 1650
    CheckIsStandard(t);

    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1648, 0); // 1651
    CheckIsNotStandard(t, "scriptsig-size");

    // Check scriptSig format (non-standard if there are any other ops than just PUSHs)
    t.vin[0].scriptSig = CScript()
        << OP_TRUE << OP_0 << OP_1NEGATE << OP_16 // OP_n (single byte pushes: n = 1, 0, -1, 16)
        << std::vector<unsigned char>(75, 0)      // OP_PUSHx [...x bytes...]
        << std::vector<unsigned char>(235, 0)     // OP_PUSHDATA1 x [...x bytes...]
        << std::vector<unsigned char>(1234, 0)    // OP_PUSHDATA2 x [...x bytes...]
        << OP_9;
    CheckIsStandard(t);

    const std::vector<unsigned char> non_push_ops = { // arbitrary set of non-push operations
        OP_NOP, OP_VERIFY, OP_IF, OP_ROT, OP_3DUP, OP_SIZE, OP_EQUAL, OP_ADD, OP_SUB,
        OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKLOCKTIMEVERIFY };

    CScript::const_iterator pc = t.vin[0].scriptSig.begin();
    while (pc < t.vin[0].scriptSig.end()) {
        opcodetype opcode;
        CScript::const_iterator prev_pc = pc;
        t.vin[0].scriptSig.GetOp(pc, opcode); // advance to next op
        // for the sake of simplicity, we only replace single-byte push operations
        if (opcode >= 1 && opcode <= OP_PUSHDATA4)
            continue;

        int index = prev_pc - t.vin[0].scriptSig.begin();
        unsigned char orig_op = *prev_pc; // save op
        // replace current push-op with each non-push-op
        for (auto op : non_push_ops) {
            t.vin[0].scriptSig[index] = op;
            CheckIsNotStandard(t, "scriptsig-not-pushonly");
        }
        t.vin[0].scriptSig[index] = orig_op; // restore op
        CheckIsStandard(t);
    }

    // Check tx-size (non-standard if transaction weight is > MAX_STANDARD_TX_WEIGHT)
    t.vin.clear();
    t.vin.resize(2438); // size per input (empty scriptSig): 41 bytes
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(19, 0); // output size: 30 bytes
    // tx header:                12 bytes =>     48 weight units
    // 2438 inputs: 2438*41 = 99958 bytes => 399832 weight units
    //    1 output:              30 bytes =>    120 weight units
    //                      ======================================
    //                                total: 400000 weight units
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction(t)), 400000);
    CheckIsStandard(t);

    // increase output size by one byte, so we end up with 400004 weight units
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(20, 0); // output size: 31 bytes
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction(t)), 400004);
    CheckIsNotStandard(t, "tx-size");

    // Check bare multisig (standard if policy flag g_bare_multi is set)
    g_bare_multi = true;
    t.vout[0].scriptPubKey = GetScriptForMultisig(1, {key.GetPubKey()}); // simple 1-of-1
    t.vin.resize(1);
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(65, 0);
    CheckIsStandard(t);

    g_bare_multi = false;
    CheckIsNotStandard(t, "bare-multisig");
    g_bare_multi = DEFAULT_PERMIT_BAREMULTISIG;

    // Add dust outputs up to allowed maximum
    assert(t.vout.size() == 1);
    t.vout.insert(t.vout.end(), MAX_DUST_OUTPUTS_PER_TX, {0, t.vout[0].scriptPubKey});

    // Check compressed P2PK outputs dust threshold (must have leading 02 or 03)
    t.vout[0].scriptPubKey = CScript() << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG;
    t.vout[0].nValue = 576;
    CheckIsStandard(t);
    t.vout[0].nValue = 575;
    CheckIsNotStandard(t, "dust");

    // Check uncompressed P2PK outputs dust threshold (must have leading 04/06/07)
    t.vout[0].scriptPubKey = CScript() << std::vector<unsigned char>(65, 0x04) << OP_CHECKSIG;
    t.vout[0].nValue = 672;
    CheckIsStandard(t);
    t.vout[0].nValue = 671;
    CheckIsNotStandard(t, "dust");

    // Check P2PKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    t.vout[0].nValue = 546;
    CheckIsStandard(t);
    t.vout[0].nValue = 545;
    CheckIsNotStandard(t, "dust");

    // Check P2SH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUAL;
    t.vout[0].nValue = 540;
    CheckIsStandard(t);
    t.vout[0].nValue = 539;
    CheckIsNotStandard(t, "dust");

    // Check P2WPKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0);
    t.vout[0].nValue = 294;
    CheckIsStandard(t);
    t.vout[0].nValue = 293;
    CheckIsNotStandard(t, "dust");

    // Check P2WSH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = 330;
    CheckIsStandard(t);
    t.vout[0].nValue = 329;
    CheckIsNotStandard(t, "dust");

    // Check P2TR outputs dust threshold (Invalid xonly key ok!)
    t.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = 330;
    CheckIsStandard(t);
    t.vout[0].nValue = 329;
    CheckIsNotStandard(t, "dust");

    // Check future Witness Program versions dust threshold (non-32-byte pushes are undefined for version 1)
    for (int op = OP_1; op <= OP_16; op += 1) {
        t.vout[0].scriptPubKey = CScript() << (opcodetype)op << std::vector<unsigned char>(2, 0);
        t.vout[0].nValue = 240;
        CheckIsStandard(t);

        t.vout[0].nValue = 239;
        CheckIsNotStandard(t, "dust");
    }

    // Check anchor outputs
    t.vout[0].scriptPubKey = CScript() << OP_1 << ANCHOR_BYTES;
    BOOST_CHECK(t.vout[0].scriptPubKey.IsPayToAnchor());
    t.vout[0].nValue = 240;
    CheckIsStandard(t);
    t.vout[0].nValue = 239;
    CheckIsNotStandard(t, "dust");
}

BOOST_AUTO_TEST_SUITE_END()
