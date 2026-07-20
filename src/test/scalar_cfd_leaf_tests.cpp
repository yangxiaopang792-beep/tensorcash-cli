// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/scalar_cfd_leaf.h>

#include <crypto/common.h> // WriteLE16 / WriteLE32 / WriteLE64
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_leaf_tests, BasicTestingSetup)

namespace {
using valtype = std::vector<unsigned char>;

valtype LE16(uint16_t v) { valtype b(2); WriteLE16(b.data(), v); return b; }
valtype LE32(uint32_t v) { valtype b(4); WriteLE32(b.data(), v); return b; }
valtype LE64(uint64_t v) { valtype b(8); WriteLE64(b.data(), v); return b; }
valtype Bytes(size_t n, unsigned char fill) { return valtype(n, fill); }

// Canonical operand bytes for a valid v1 leaf. Each field is mutated independently to
// drive the negative cases; the structural opcodes are added by the builders below.
struct Parts {
    valtype contract_id   = Bytes(32, 0x11);
    valtype tmpl_version  = {SCALAR_CFD_TEMPLATE_VERSION_V1};
    valtype settle_lock   = CScriptNum(800000).getvch();                 // 3-byte minimal push
    valtype source_type   = {static_cast<unsigned char>(ScalarCfdSourceType::ISSUER_PUBLISHED)};
    valtype underlying    = Bytes(32, 0x22);
    valtype feed_id       = LE32(7);
    valtype fixing_ref    = LE64(0x1122334455667788ull);
    valtype deadline      = LE32(900000);
    valtype payoff_mode   = {static_cast<unsigned char>(ScalarCfdPayoffMode::STRIKE)};
    valtype scalar_format = LE16(1);                                     // SCALAR_FORMAT_RAW_U256_LE
    valtype strike        = Bytes(32, 0x33);
    valtype fallback      = Bytes(32, 0x44);
    valtype lambda_q      = LE32(10u << 16);                             // Q16 leverage 10
    valtype loss_dir      = {0x01};
    valtype collateral    = Bytes(32, 0x00);                            // NATIVE_SENTINEL
    valtype vault_im      = LE64(1'000'000'000);
    valtype owner         = Bytes(32, 0x55);
    valtype cp            = Bytes(32, 0x66);
};

// Append everything AFTER <contract_id> OP_DROP, ending at the terminal opcode. Split
// out so the push-form negative tests can supply a non-canonical contract_id prefix.
void AppendBody(CScript& s, const Parts& p)
{
    s << p.tmpl_version;
    s << p.settle_lock << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    s << p.source_type;
    s << p.underlying;
    s << p.feed_id;
    s << p.fixing_ref;
    s << p.deadline;
    s << p.payoff_mode;
    s << p.scalar_format;
    s << p.strike;
    s << p.fallback;
    s << p.lambda_q;
    s << p.loss_dir;
    s << p.collateral;
    s << p.vault_im;
    s << p.owner;
    s << p.cp;
    s << OP_SCALAR_CFD_SETTLE;
}

CScript Build(const Parts& p)
{
    CScript s;
    s << p.contract_id << OP_DROP;
    AppendBody(s, p);
    return s;
}
} // namespace

// ---- Positive -------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(canonical_leaf_round_trips)
{
    const Parts p;
    ScalarCfdLeaf out;
    BOOST_REQUIRE(ParseScalarCfdLeaf(Build(p), out));

    BOOST_CHECK(out.contract_id == uint256{p.contract_id});
    BOOST_CHECK_EQUAL(out.template_version, SCALAR_CFD_TEMPLATE_VERSION_V1);
    BOOST_CHECK_EQUAL(out.settle_lock_height, 800000);
    BOOST_CHECK_EQUAL(out.source_type, static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED));
    BOOST_CHECK(out.underlying_asset_id == uint256{p.underlying});
    BOOST_CHECK_EQUAL(out.feed_id, 7u);
    BOOST_CHECK_EQUAL(out.fixing_ref, 0x1122334455667788ull);
    BOOST_CHECK_EQUAL(out.publication_deadline_height, 900000u);
    BOOST_CHECK_EQUAL(out.payoff_mode, static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE));
    BOOST_CHECK_EQUAL(out.scalar_format_id, 1u);
    BOOST_CHECK(out.strike == uint256{p.strike});
    BOOST_CHECK(out.fallback_scalar == uint256{p.fallback});
    BOOST_CHECK_EQUAL(out.lambda_q, 10u << 16);
    BOOST_CHECK_EQUAL(out.loss_direction, 0x01);
    BOOST_CHECK(out.collateral_asset_id == uint256{}); // all-zero sentinel
    BOOST_CHECK_EQUAL(out.vault_im, 1'000'000'000ull);
    BOOST_CHECK(out.owner_key == p.owner);
    BOOST_CHECK(out.cp_key == p.cp);
}

BOOST_AUTO_TEST_CASE(accepts_chain_intrinsic_and_realized_and_short)
{
    Parts p;
    p.source_type = {static_cast<unsigned char>(ScalarCfdSourceType::CHAIN_INTRINSIC)};
    p.underlying = Bytes(32, 0x00); // CHAIN_INTRINSIC has no underlying -> U pinned to zero
    p.payoff_mode = {static_cast<unsigned char>(ScalarCfdPayoffMode::REALIZED)};
    p.loss_dir = {0x00};
    ScalarCfdLeaf out;
    BOOST_REQUIRE(ParseScalarCfdLeaf(Build(p), out));
    BOOST_CHECK_EQUAL(out.source_type, static_cast<uint8_t>(ScalarCfdSourceType::CHAIN_INTRINSIC));
    BOOST_CHECK(out.underlying_asset_id == uint256{});
    BOOST_CHECK_EQUAL(out.payoff_mode, static_cast<uint8_t>(ScalarCfdPayoffMode::REALIZED));
    BOOST_CHECK_EQUAL(out.loss_direction, 0x00);
}

BOOST_AUTO_TEST_CASE(rejects_chain_intrinsic_with_nonzero_underlying)
{
    // CHAIN_INTRINSIC must commit a zero underlying; a non-zero U is malleability, rejected.
    Parts p;
    p.source_type = {static_cast<unsigned char>(ScalarCfdSourceType::CHAIN_INTRINSIC)};
    p.underlying = Bytes(32, 0x22); // non-zero
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

BOOST_AUTO_TEST_CASE(accepts_asset_collateral)
{
    Parts p;
    p.collateral = Bytes(32, 0x77); // non-zero asset id
    ScalarCfdLeaf out;
    BOOST_REQUIRE(ParseScalarCfdLeaf(Build(p), out));
    BOOST_CHECK(out.collateral_asset_id == uint256{p.collateral});
}

BOOST_AUTO_TEST_CASE(scalar_format_id_extracted_not_validated)
{
    // The format catalogue is an eval/resolution concern; the parser must extract any
    // 2-byte id verbatim without rejecting unknown ones.
    Parts p;
    p.scalar_format = LE16(0xBEEF);
    ScalarCfdLeaf out;
    BOOST_REQUIRE(ParseScalarCfdLeaf(Build(p), out));
    BOOST_CHECK_EQUAL(out.scalar_format_id, 0xBEEFu);
}

// ---- Negative: enum/version guards ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(rejects_unknown_template_version)
{
    Parts p; p.tmpl_version = {0x02};
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

BOOST_AUTO_TEST_CASE(rejects_out_of_range_source_type)
{
    Parts p; p.source_type = {0x02};
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

BOOST_AUTO_TEST_CASE(rejects_deferred_payoff_mode_two)
{
    Parts p; p.payoff_mode = {0x02}; // mode 2 (FIXED-REF) needs a v2 template
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

BOOST_AUTO_TEST_CASE(rejects_out_of_range_loss_direction)
{
    Parts p; p.loss_dir = {0x02};
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

// ---- Negative: operand lengths --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(rejects_wrong_blob_lengths)
{
    {
        Parts p; p.feed_id = LE16(7); // 2 bytes where 4 are required
        ScalarCfdLeaf out;
        BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
    }
    {
        Parts p; p.vault_im = LE32(1); // 4 bytes where 8 are required
        ScalarCfdLeaf out;
        BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
    }
    {
        Parts p; p.contract_id = Bytes(31, 0x11); // 31 bytes where 32 are required
        ScalarCfdLeaf out;
        BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
    }
    {
        Parts p; p.scalar_format = {0x01}; // 1 byte where 2 are required
        ScalarCfdLeaf out;
        BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
    }
}

// ---- Negative: push-form discipline ---------------------------------------------------------

BOOST_AUTO_TEST_CASE(rejects_pushdata_for_direct_push_field)
{
    // contract_id via OP_PUSHDATA1 instead of OP_PUSHBYTES_32; body otherwise canonical.
    CScript s;
    s.push_back(OP_PUSHDATA1);
    s.push_back(0x20);
    for (int i = 0; i < 32; ++i) s.push_back(0x11); // 32-byte payload, byte-by-byte (avoids a
                                                    // prevector fortified-memmove false positive)
    s << OP_DROP;
    AppendBody(s, Parts{});
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(s, out));
}

BOOST_AUTO_TEST_CASE(rejects_op1_for_loss_direction)
{
    // loss_direction as the bare opcode OP_1 (0x51) instead of a raw 1-byte data push —
    // a different leaf byte and a different tapleaf hash (§2.2).
    const Parts p;
    CScript s;
    s << p.contract_id << OP_DROP;
    s << p.tmpl_version;
    s << p.settle_lock << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    s << p.source_type;
    s << p.underlying;
    s << p.feed_id;
    s << p.fixing_ref;
    s << p.deadline;
    s << p.payoff_mode;
    s << p.scalar_format;
    s << p.strike;
    s << p.fallback;
    s << p.lambda_q;
    s << OP_1; // <-- not a push
    s << p.collateral;
    s << p.vault_im;
    s << p.owner;
    s << p.cp;
    s << OP_SCALAR_CFD_SETTLE;
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(s, out));
}

// ---- Negative: CLTV operand canonicality ----------------------------------------------------

BOOST_AUTO_TEST_CASE(rejects_non_minimal_settle_lock)
{
    Parts p;
    p.settle_lock = {0x00, 0x35, 0x0C, 0x00}; // 800000 with a trailing zero -> non-minimal
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

BOOST_AUTO_TEST_CASE(rejects_negative_settle_lock)
{
    Parts p;
    p.settle_lock = {0x81}; // CScriptNum -1
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

BOOST_AUTO_TEST_CASE(rejects_oversize_settle_lock)
{
    Parts p;
    p.settle_lock = Bytes(6, 0x01); // 6 bytes > CScriptNum's 5-byte locktime cap
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(Build(p), out));
}

// ---- Negative: structure --------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(rejects_missing_drop_after_contract_id)
{
    const Parts p;
    CScript s;
    s << p.contract_id; // no OP_DROP
    AppendBody(s, p);
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(s, out));
}

BOOST_AUTO_TEST_CASE(rejects_trailing_bytes)
{
    CScript s = Build(Parts{});
    s << OP_NOP1; // anything after the terminal opcode
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(s, out));
}

BOOST_AUTO_TEST_CASE(rejects_missing_terminal_opcode)
{
    const Parts p;
    CScript s;
    s << p.contract_id << OP_DROP;
    s << p.tmpl_version;
    s << p.settle_lock << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    s << p.source_type << p.underlying << p.feed_id << p.fixing_ref << p.deadline
      << p.payoff_mode << p.scalar_format << p.strike << p.fallback << p.lambda_q
      << p.loss_dir << p.collateral << p.vault_im << p.owner << p.cp;
    // terminal OP_SCALAR_CFD_SETTLE omitted
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(s, out));
}

BOOST_AUTO_TEST_CASE(rejects_truncated_leaf)
{
    const CScript full = Build(Parts{});
    const CScript trunc(full.begin(), full.end() - 40); // cuts into the cp_key push
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(trunc, out));
}

BOOST_AUTO_TEST_CASE(rejects_empty_script)
{
    ScalarCfdLeaf out;
    BOOST_CHECK(!ParseScalarCfdLeaf(CScript{}, out));
}

BOOST_AUTO_TEST_SUITE_END()
