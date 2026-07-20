// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Interpreter-level tests for OP_NBITS_AT + OP_DIFFCFD_SETTLE, driven through the real EvalScript
// with a mock FixingContext (see DIFFICULTY_DERIVATIVE.md §3.1/§3.2). A default ScriptExecutionData
// has m_witness_version == 1, so SigVersion::TAPSCRIPT here exercises the v1 path; the v2 path is
// exercised by setting m_witness_version = 2.

#include <arith_uint256.h>
#include <assets/asset.h>
#include <consensus/amount.h>
#include <consensus/difficulty_cfd.h>
#include <crypto/common.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(difficulty_cfd_script_tests, BasicTestingSetup)

namespace {

// Mock fixing resolver: a height->nBits map, a configurable ContextHeight, and DecodeTarget wrapping
// the real DeriveTarget with a max powLimit (so any in-range compact decodes).
class MockFixingContext final : public FixingContext
{
public:
    std::map<int, uint32_t> nbits_by_height;
    int context_height{0};
    int maturity{0};
    uint256 pow_limit{ArithToUint256(~arith_uint256{0})}; // all-ones: accept any in-range target

    std::optional<uint32_t> NBitsAt(int height) const override
    {
        // Faithful to ChainFixingContext: enforce the consensus burial bound before resolving.
        if (!DiffCfdFixingResolvable(height, context_height, maturity)) return std::nullopt;
        auto it = nbits_by_height.find(height);
        if (it == nbits_by_height.end()) return std::nullopt;
        return it->second;
    }
    int ContextHeight() const override { return context_height; }
    std::optional<arith_uint256> DecodeTarget(uint32_t nBits) const override
    {
        return DeriveTarget(nBits, pow_limit);
    }
};

std::vector<unsigned char> LE32(uint32_t v)
{
    std::vector<unsigned char> b(4);
    WriteLE32(b.data(), v);
    return b;
}
std::vector<unsigned char> LE64(uint64_t v)
{
    std::vector<unsigned char> b(8);
    WriteLE64(b.data(), v);
    return b;
}
std::vector<unsigned char> Key(unsigned char fill) { return std::vector<unsigned char>(32, fill); }
CScript P2TR(const std::vector<unsigned char>& key32) { return CScript() << OP_1 << key32; }

// Local copy of the interpreter's CastToBool (which is file-static): a stack element is true unless
// it is empty or all-zero (allowing a trailing 0x80 negative-zero byte).
bool IsTruthy(const std::vector<unsigned char>& vch)
{
    for (size_t i = 0; i < vch.size(); ++i) {
        if (vch[i] != 0) {
            if (i == vch.size() - 1 && vch[i] == 0x80) return false;
            return true;
        }
    }
    return false;
}

// Canonical compact for a given integer target (round-trips through GetCompact/DeriveTarget).
uint32_t CanonicalNBits(uint64_t target_value)
{
    arith_uint256 t{target_value};
    return t.GetCompact();
}

std::vector<unsigned char> AssetTag(const uint256& asset_id, uint64_t amount)
{
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(40); // compact size for 32 + 8
    tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
    unsigned char buf[8];
    WriteLE64(buf, amount);
    tlv.insert(tlv.end(), buf, buf + 8);
    return tlv;
}

// <fixing_height_le4> <strike_le4> <lambda_q_le4> <dir> <vault_im_le8> <owner_key> <cp_key> OP_DIFFCFD_SETTLE
// OP_DIFFCFD_SETTLE resolves realized nBits @ fixing_height from the FixingContext ITSELF (folded;
// realized is never taken from the stack, so a committed leaf cannot forge it).
CScript BuildLeaf(const std::vector<unsigned char>& height_push, uint32_t strike_nbits, uint32_t lambda_q,
                  uint8_t dir, uint64_t vault_im,
                  const std::vector<unsigned char>& owner_key, const std::vector<unsigned char>& cp_key)
{
    CScript s;
    s << height_push;
    s << LE32(strike_nbits);
    s << LE32(lambda_q);
    s << std::vector<unsigned char>{dir};
    s << LE64(vault_im);
    s << owner_key;
    s << cp_key;
    s << OP_DIFFCFD_SETTLE;
    return s;
}

// Run a leaf through EvalScript. Returns SCRIPT_ERR_OK on a truthy success, else the set error.
ScriptError RunLeaf(const CScript& leaf, const CTransaction& tx, uint64_t input_amount,
                    const FixingContext* fixing, int witness_version = 1,
                    unsigned int flags = SCRIPT_VERIFY_TAPROOT)
{
    std::vector<std::vector<unsigned char>> stack;
    ScriptExecutionData execdata;
    execdata.m_witness_version = witness_version;
    TransactionSignatureChecker checker(&tx, 0, static_cast<CAmount>(input_amount),
                                        MissingDataBehavior::FAIL, fixing);
    ScriptError err = SCRIPT_ERR_OK;
    const bool ok = EvalScript(stack, leaf, flags, checker, SigVersion::TAPSCRIPT, execdata, &err);
    if (!ok) return err;
    BOOST_CHECK_MESSAGE(!stack.empty() && IsTruthy(stack.back()), "leaf succeeded but left a falsy stack");
    return SCRIPT_ERR_OK;
}

// Common terms shared across cases.
constexpr int H = 50;
constexpr uint32_t LAMBDA10 = 10 * static_cast<uint32_t>(DIFFCFD_LAMBDA_SCALE);
constexpr uint64_t IM = 1'000'000'000;

// Build a tx whose outputs satisfy the payout the opcode will compute for these terms, given a
// realized nBits resolved at height H. Returns {tx, payout} so tests can tweak outputs/amounts.
struct Built {
    CMutableTransaction mtx;
    DiffCfdPayout payout;
    uint32_t strike_nbits;
    uint32_t realized_nbits;
};

Built BuildMatching(uint64_t strike_target, uint64_t realized_target, uint32_t lambda_q, uint64_t vault_im,
                    bool short_leg, const std::vector<unsigned char>& owner_key,
                    const std::vector<unsigned char>& cp_key)
{
    Built out;
    out.strike_nbits = CanonicalNBits(strike_target);
    out.realized_nbits = CanonicalNBits(realized_target);
    const uint256 powlim = ArithToUint256(~arith_uint256{0});
    const auto K = DeriveTarget(out.strike_nbits, powlim);
    const auto S = DeriveTarget(out.realized_nbits, powlim);
    BOOST_REQUIRE(K && S);
    BOOST_REQUIRE(ComputeDiffCfdPayout(*K, *S, lambda_q, vault_im, short_leg, out.payout));

    out.mtx.vin.emplace_back();
    if (out.payout.payout_owner > 0) out.mtx.vout.emplace_back(static_cast<CAmount>(out.payout.payout_owner), P2TR(owner_key));
    if (out.payout.payout_cp > 0) out.mtx.vout.emplace_back(static_cast<CAmount>(out.payout.payout_cp), P2TR(cp_key));
    return out;
}

} // namespace

// ---- Positive cases -------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(settle_short_partial_two_outputs)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    // realized target 5% below strike -> short leg loses ~0.5 of margin (both legs non-zero)
    Built b = BuildMatching(/*strike=*/1'000'000, /*realized=*/950'000, LAMBDA10, IM, /*short=*/true, owner, cp);
    BOOST_CHECK(b.payout.payout_owner > 0 && b.payout.payout_cp > 0); // genuinely "both outputs"
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(settle_flat_owner_only)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    // realized == strike -> short owner keeps full margin, single owner output
    Built b = BuildMatching(1'000'000, 1'000'000, LAMBDA10, IM, /*short=*/true, owner, cp);
    BOOST_CHECK(b.payout.payout_cp == 0 && b.payout.payout_owner == IM);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(settle_full_liquidation_cp_only)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    // realized 20% below strike, lambda 10 -> full liquidation, single cp output
    Built b = BuildMatching(1'000'000, 800'000, LAMBDA10, IM, /*short=*/true, owner, cp);
    BOOST_CHECK(b.payout.payout_owner == 0 && b.payout.payout_cp == IM);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(settle_long_down)
{
    const auto owner = Key(0xC3), cp = Key(0xD4);
    // long leg: realized target above strike (difficulty fell) -> long loses ~0.5
    Built b = BuildMatching(/*strike=*/950'000, /*realized=*/1'000'000, LAMBDA10, IM, /*short=*/false, owner, cp);
    BOOST_CHECK(b.payout.payout_owner > 0 && b.payout.payout_cp > 0);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x00, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_OK);
}

// ---- Negative cases -------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(no_fixing_context)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    // checker built with fixing = nullptr -> OP_NBITS_AT fails closed
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, /*fixing=*/nullptr), SCRIPT_ERR_DIFFCFD_CONTEXT);
}

BOOST_AUTO_TEST_CASE(bad_height_length)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    // 3-byte height push instead of 4
    const CScript leaf = BuildLeaf(std::vector<unsigned char>(3, 0x05), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(height_at_or_above_context)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H; ctx.nbits_by_height[H] = b.realized_nbits; // H not < H
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_HEIGHT);
}

BOOST_AUTO_TEST_CASE(unresolvable_height)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; // map left empty -> NBitsAt returns nullopt
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_HEIGHT);
}

BOOST_AUTO_TEST_CASE(bad_loss_direction)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, /*dir=*/0x02, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(noncanonical_strike)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    // 0x03001234 decodes to target 0x1234 but GetCompact() normalizes to 0x02123400 != 0x03001234
    const CScript leaf = BuildLeaf(LE32(H), /*strike=*/0x03001234u, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_ENCODING);
}

BOOST_AUTO_TEST_CASE(wrong_input_amount)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    // spent amount != committed vault_im
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM - 1, &ctx), SCRIPT_ERR_DIFFCFD_AMOUNT);
}

BOOST_AUTO_TEST_CASE(missing_output)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    b.mtx.vout.clear(); // drop the required settlement outputs
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_OUTPUTS);
}

BOOST_AUTO_TEST_CASE(wrong_output_spk)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    // rewrite the cp output to a different key, keeping the amount
    for (auto& o : b.mtx.vout) {
        if (o.scriptPubKey == P2TR(cp)) o.scriptPubKey = P2TR(Key(0xEE));
    }
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_OUTPUTS);
}

BOOST_AUTO_TEST_CASE(asset_tagged_output_rejected)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    // tag the cp output with an asset TLV: native covenant must NOT accept it
    uint256 asset_id; asset_id.data()[0] = 0x77;
    for (auto& o : b.mtx.vout) {
        if (o.scriptPubKey == P2TR(cp)) o.vExt = AssetTag(asset_id, /*amount=*/123);
    }
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_OUTPUTS);
}

// Distinct-output rule: owner and cp share a key with a positive split -> two DISTINCT outputs needed.
BOOST_AUTO_TEST_CASE(distinct_outputs_required_same_key)
{
    const auto shared = Key(0x5A);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, shared, shared);
    BOOST_REQUIRE(b.payout.payout_owner > 0 && b.payout.payout_cp > 0);

    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, shared, shared);

    // Two distinct outputs (owner amount + cp amount) -> passes.
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx), SCRIPT_ERR_OK);

    // Collapse to a single output carrying only one leg's amount -> the other leg has no distinct
    // output to bind, so the covenant fails.
    if (b.payout.payout_owner != b.payout.payout_cp) {
        CMutableTransaction one = b.mtx;
        one.vout.resize(1); // keep only the first (owner) output
        BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(one), IM, &ctx), SCRIPT_ERR_DIFFCFD_OUTPUTS);
    }
}

// v2 witness path: the very same leaf must fail SCRIPT_ERR_DIFFCFD_CONTEXT (v2 also runs as TAPSCRIPT).
BOOST_AUTO_TEST_CASE(v2_witness_rejected)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const CScript leaf = BuildLeaf(LE32(H), b.strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(b.mtx), IM, &ctx, /*witness_version=*/2), SCRIPT_ERR_DIFFCFD_CONTEXT);
}

// FORGERY: realized nBits is resolved by consensus from the committed fixing_height — it can NOT be
// injected via the stack. A malicious leaf that pushes a fake realized value (e.g. via
// <H> OP_NBITS_AT OP_DROP <fake>) only shifts which operand OP_DIFFCFD_SETTLE reads as the height; the
// fake compact value interpreted as a height is far out of range, so settlement fails closed.
BOOST_AUTO_TEST_CASE(realized_cannot_be_forged)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;

    const uint32_t fake_realized = CanonicalNBits(800'000); // attacker wants full-liquidation realized
    CScript leaf;
    leaf << LE32(H) << OP_NBITS_AT << OP_DROP;   // resolve+discard the real value, then push a fake
    leaf << LE32(fake_realized);                 // <-- this becomes the fixing_height operand SETTLE reads
    leaf << LE32(b.strike_nbits) << LE32(LAMBDA10) << std::vector<unsigned char>{0x01}
         << LE64(IM) << owner << cp << OP_DIFFCFD_SETTLE;

    // Build outputs matching the FAKE full-liquidation payout the attacker hoped for.
    CMutableTransaction mtx; mtx.vin.emplace_back();
    mtx.vout.emplace_back(static_cast<CAmount>(IM), P2TR(cp));
    // fake_realized (~5e7) interpreted as a height is >> context_height -> NBitsAt fails.
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(mtx), IM, &ctx), SCRIPT_ERR_DIFFCFD_HEIGHT);
}

// CLTV (full §2.2 leaf shape): early settlement is blocked by the lock height; mature settlement runs
// through to OP_DIFFCFD_SETTLE. (Consensus also enforces burial via the maturity bound; this checks
// the leaf's belt-and-suspenders CLTV prefix.)
BOOST_AUTO_TEST_CASE(cltv_gate)
{
    const auto owner = Key(0xA1), cp = Key(0xB2);
    Built b = BuildMatching(1'000'000, 950'000, LAMBDA10, IM, true, owner, cp);
    MockFixingContext ctx; ctx.context_height = H + 1; ctx.nbits_by_height[H] = b.realized_nbits;
    const int lock_height = H + DIFFCFD_MATURITY_DEPTH;

    CScript leaf;
    leaf << int64_t{lock_height} << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    leaf << LE32(H) << LE32(b.strike_nbits) << LE32(LAMBDA10) << std::vector<unsigned char>{0x01}
         << LE64(IM) << owner << cp << OP_DIFFCFD_SETTLE;

    const unsigned int flags = SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

    // Early: tx nLockTime below lock_height, input non-final -> CLTV fails.
    CMutableTransaction early = b.mtx;
    early.nLockTime = lock_height - 1;
    early.vin[0].nSequence = 0;
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(early), IM, &ctx, 1, flags), SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    // Mature: tx nLockTime at lock_height -> CLTV passes, settlement succeeds.
    CMutableTransaction mature = b.mtx;
    mature.nLockTime = lock_height;
    mature.vin[0].nSequence = 0;
    BOOST_CHECK_EQUAL(RunLeaf(leaf, CTransaction(mature), IM, &ctx, 1, flags), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
