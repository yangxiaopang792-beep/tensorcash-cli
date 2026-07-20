// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Exercises the consensus pre-scan wiring for OP_SCALAR_CFD_SETTLE (CFD_GENERALISATION.md §3.4/§3.6):
// the SHARED one-settle-input rule (difficulty + scalar counted together), the conservative
// opcode-byte detection (counts even when the leaf is non-canonical), and the activation gate (the
// scan runs only when SCRIPT_VERIFY_SCALAR_CFD is set), driven through the real CheckInputScripts.

#include <addresstype.h>
#include <arith_uint256.h>
#include <assets/registry.h>
#include <coins.h>
#include <consensus/difficulty_cfd.h>
#include <consensus/scalar_cfd.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

// Production CheckInputScripts (redeclared as in the difficulty validation tests).
bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks,
                       const FixingContext* fixing) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_FIXTURE_TEST_SUITE(scalar_cfd_validation_tests, TestChain100Setup)

namespace {
using valtype = std::vector<unsigned char>;

valtype Key(unsigned char fill) { return valtype(32, fill); }
CScript P2TR(const valtype& k) { return CScript() << OP_1 << k; }

// A minimal v1 tapscript leaf that merely CONTAINS OP_SCALAR_CFD_SETTLE (not canonical): enough for
// the conservative pre-scan to count it, proving detection is independent of parse success.
valtype ScalarLeafBytes()
{
    CScript s; s << OP_TRUE << OP_SCALAR_CFD_SETTLE;
    return valtype(s.begin(), s.end());
}

valtype DifficultyLeafBytes()
{
    CScript s; s << OP_TRUE << OP_DIFFCFD_SETTLE;
    return valtype(s.begin(), s.end());
}

// Bogus-but-well-formed v1 control block (33 bytes, leaf version 0xc0): enough for the pre-scan to
// recognise a revealed leaf; the commitment is never checked because the one-input rule rejects
// before script execution.
valtype BogusControl()
{
    valtype c(TAPROOT_CONTROL_BASE_SIZE, 0x00);
    c[0] = TAPROOT_LEAF_TAPSCRIPT;
    return c;
}

Txid FakeTxid(unsigned char fill) { uint256 h; std::memset(h.data(), fill, h.size()); return Txid::FromUint256(h); }

valtype LE16(uint16_t v) { valtype b(2); WriteLE16(b.data(), v); return b; }
valtype LE32(uint32_t v) { valtype b(4); WriteLE32(b.data(), v); return b; }
valtype LE64(uint64_t v) { valtype b(8); WriteLE64(b.data(), v); return b; }
valtype ToVec(const uint256& u) { return valtype(u.begin(), u.end()); }
uint256 U256(uint8_t b) { return uint256{valtype(32, b)}; }
uint256 A256(uint64_t v) { return ArithToUint256(arith_uint256(v)); }

// Minimal FixingContext exposing only a context height (the scalar resolver uses nothing else).
class CtxHeightFixing final : public FixingContext {
public:
    int h;
    explicit CtxHeightFixing(int height) : h(height) {}
    std::optional<uint32_t> NBitsAt(int) const override { return std::nullopt; }
    int ContextHeight() const override { return h; }
    std::optional<arith_uint256> DecodeTarget(uint32_t) const override { return std::nullopt; }
};

// The FULL canonical §2.2 leaf (ISSUER_PUBLISHED, native collateral, STRIKE mode, long), so it
// parses and resolves through the real pre-scan. settle_lock uses a minimal CScriptNum push.
CScript BuildCanonicalLeaf(const uint256& underlying, uint32_t feed_id, uint64_t fixing_ref,
                           uint32_t deadline, const uint256& strike, uint16_t fmt, uint32_t lambda_q,
                           uint64_t vault_im, const valtype& owner, const valtype& cp, uint32_t settle_lock)
{
    CScript s;
    s << valtype(32, 0x01) << OP_DROP;                                 // contract_id
    s << valtype{0x01};                                               // template_version
    s << CScriptNum(settle_lock).getvch() << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    s << valtype{0x00};                                               // source_type = ISSUER_PUBLISHED
    s << ToVec(underlying);
    s << LE32(feed_id) << LE64(fixing_ref) << LE32(deadline);
    s << valtype{0x00};                                               // payoff_mode = STRIKE
    s << LE16(fmt);
    s << ToVec(strike) << ToVec(A256(95));                            // strike, fallback_scalar
    s << LE32(lambda_q);
    s << valtype{0x00};                                               // loss_direction = long
    s << ToVec(uint256{});                                            // collateral = NATIVE_SENTINEL
    s << LE64(vault_im);
    s << owner << cp;
    s << OP_SCALAR_CFD_SETTLE;
    return s;
}

constexpr unsigned int BASE_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT;
constexpr CAmount IM = 1'000'000'000;

// Build a 2-input tx, each input revealing one of the given leaves (with a bogus control block),
// run the real CheckInputScripts, and return the reject reason. Every case here fails (the
// one-settle-input rule, or the bogus taproot commitment).
std::string RunTwoLeaves(TestChain100Setup& setup, const valtype& leaf0, const valtype& leaf1, unsigned int flags)
{
    CCoinsViewCache view(&setup.m_node.chainman->ActiveChainstate().CoinsTip());
    const valtype leaves[2] = {leaf0, leaf1};
    CMutableTransaction mtx;
    for (size_t i = 0; i < 2; ++i) {
        const auto tag = static_cast<unsigned char>(0x30 + i);
        const COutPoint op{FakeTxid(tag), 0};
        view.AddCoin(op, Coin(CTxOut(IM, P2TR(Key(tag))), 1, false), false);
        CTxIn in(op);
        in.scriptWitness.stack = {leaves[i], BogusControl()};
        mtx.vin.push_back(in);
    }
    mtx.vout.emplace_back(CAmount{1000}, P2TR(Key(0xCC)));

    TxValidationState state;
    PrecomputedTransactionData txdata;
    const bool ok = CheckInputScripts(CTransaction(mtx), state, view, flags, true, true, txdata,
                                      setup.m_node.chainman->m_validation_cache, nullptr, nullptr);
    BOOST_CHECK(!ok);
    return state.GetRejectReason();
}
} // namespace

BOOST_AUTO_TEST_CASE(rejects_two_scalar_inputs)
{
    LOCK(cs_main);
    // Two leaves containing OP_SCALAR_CFD_SETTLE (non-canonical) -> conservative count 2 -> rejected
    // before any script execution. Proves detection is independent of parse success.
    BOOST_CHECK_EQUAL(RunTwoLeaves(*this, ScalarLeafBytes(), ScalarLeafBytes(), BASE_FLAGS | SCRIPT_VERIFY_SCALAR_CFD),
                      "bad-txns-diffcfd-multiple-inputs");
}

BOOST_AUTO_TEST_CASE(rejects_mixed_difficulty_and_scalar_inputs)
{
    LOCK(cs_main);
    // One difficulty leaf + one scalar leaf -> counted TOGETHER (§3.6) -> rejected.
    BOOST_CHECK_EQUAL(RunTwoLeaves(*this, DifficultyLeafBytes(), ScalarLeafBytes(), BASE_FLAGS | SCRIPT_VERIFY_SCALAR_CFD),
                      "bad-txns-diffcfd-multiple-inputs");
}

BOOST_AUTO_TEST_CASE(scalar_pushdata_byte_not_counted)
{
    LOCK(cs_main);
    // A 0xb9 byte INSIDE a push is not an opcode (GetOp): one real scalar leaf + one pushdata leaf
    // -> count 1 -> NOT the multi-input rejection (fails later on the bogus commitment instead).
    CScript pushdata; pushdata << valtype{static_cast<unsigned char>(OP_SCALAR_CFD_SETTLE)} << OP_DROP << OP_TRUE;
    const valtype push_vec(pushdata.begin(), pushdata.end());
    BOOST_CHECK(RunTwoLeaves(*this, ScalarLeafBytes(), push_vec, BASE_FLAGS | SCRIPT_VERIFY_SCALAR_CFD)
                != "bad-txns-diffcfd-multiple-inputs");
}

BOOST_AUTO_TEST_CASE(pre_activation_scalar_leaves_not_counted)
{
    LOCK(cs_main);
    // WITHOUT the activation flag, the scalar scan does not run, so two 0xb9 (OP_NOP10) leaves are
    // NOT rejected by the one-settle-input rule -> no pre-activation consensus change.
    BOOST_CHECK(RunTwoLeaves(*this, ScalarLeafBytes(), ScalarLeafBytes(), BASE_FLAGS)
                != "bad-txns-diffcfd-multiple-inputs");
}

// The plan-critical happy path: canonical leaf parse -> scalar index read -> snapshot stored in
// txdata -> the opcode executes and settles. Also runs the queued check (pvChecks) to prove the
// snapshot survives into the deferred worker execution.
BOOST_AUTO_TEST_CASE(settles_canonical_native_vault_and_survives_worker_queue)
{
    LOCK(cs_main);
    CCoinsViewCache view(&m_node.chainman->ActiveChainstate().CoinsTip());

    const uint256 underlying = U256(0x22);
    const uint32_t feed_id = 7;
    const uint64_t fixing_ref = 1000;
    const uint16_t fmt = 1; // SCALAR_FORMAT_RAW_U256_LE
    const uint256 strike = A256(100);
    const auto owner = Key(0xA1), cp = Key(0xB2);

    // Stage a published scalar X=90 at height 50 (buried: 50 <= 200 - maturity 100).
    ScalarRecord rec; rec.scalar = A256(90); rec.publication_height = 50; rec.scalar_format_id = fmt;
    view.StageAssetScalar(underlying, feed_id, fixing_ref, rec);

    // Expected payout: STRIKE long, X=90 < K=100 -> cp = 0.1 * IM, owner = 0.9 * IM.
    ScalarCfdPayout payout;
    BOOST_REQUIRE(ComputeScalarCfdPayout(UintToArith256(strike), arith_uint256(90),
                                         ScalarLossDenominator::STRIKE, /*lambda_q=*/1u << 16, IM,
                                         /*short_leg=*/false, static_cast<uint64_t>(MIN_SETTLE_OUTPUT), payout));
    BOOST_REQUIRE(payout.payout_owner > 0 && payout.payout_cp > 0);

    const CScript leaf = BuildCanonicalLeaf(underlying, feed_id, fixing_ref, /*deadline=*/100, strike,
                                            fmt, /*lambda_q=*/1u << 16, IM, owner, cp, /*settle_lock=*/100);
    const valtype leafvec(leaf.begin(), leaf.end());

    // Real Taproot vault committing to the leaf, so the control block verifies.
    unsigned char seckey[32]; std::memset(seckey, 0x01, sizeof(seckey));
    CKey key; key.Set(seckey, seckey + 32, /*fCompressedIn=*/true);
    BOOST_REQUIRE(key.IsValid());
    const XOnlyPubKey internal(key.GetPubKey());
    TaprootBuilder builder; builder.Add(0, leafvec, TAPROOT_LEAF_TAPSCRIPT); builder.Finalize(internal);
    BOOST_REQUIRE(builder.IsComplete());
    const CScript spk = GetScriptForDestination(builder.GetOutput());
    const TaprootSpendData spend = builder.GetSpendData();
    auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    BOOST_REQUIRE(it != spend.scripts.end() && !it->second.empty());
    const valtype control = *it->second.begin();

    const COutPoint vault{FakeTxid(0x55), 0};
    view.AddCoin(vault, Coin(CTxOut(IM, spk), 1, false), false);

    CMutableTransaction mtx;
    mtx.nLockTime = 100; // satisfy the leaf CLTV (settle_lock = 100)
    CTxIn in(vault); in.nSequence = 0; in.scriptWitness.stack = {leafvec, control};
    mtx.vin.push_back(in);
    mtx.vout.emplace_back(static_cast<CAmount>(payout.payout_owner), P2TR(owner));
    mtx.vout.emplace_back(static_cast<CAmount>(payout.payout_cp), P2TR(cp));
    const CTransaction tx{mtx};

    CtxHeightFixing fixing(/*height=*/200);
    const unsigned int flags = BASE_FLAGS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_SCALAR_CFD;

    // Inline: end-to-end valid settlement (parse -> index read -> snapshot -> opcode execute).
    TxValidationState state1;
    PrecomputedTransactionData txdata1;
    BOOST_CHECK(CheckInputScripts(tx, state1, view, flags, true, true, txdata1,
                                  m_node.chainman->m_validation_cache, nullptr, &fixing));
    BOOST_CHECK(txdata1.m_scalar_snapshot != nullptr); // the snapshot was built and stored

    // Queued via pvChecks: the bypassed cache forces re-validation, and each deferred check reads
    // the snapshot from txdata2 (alive past CheckInputScripts), proving worker-lifetime correctness.
    TxValidationState state2;
    PrecomputedTransactionData txdata2;
    std::vector<CScriptCheck> checks;
    BOOST_CHECK(CheckInputScripts(tx, state2, view, flags, true, true, txdata2,
                                  m_node.chainman->m_validation_cache, &checks, &fixing));
    BOOST_REQUIRE_EQUAL(checks.size(), tx.vin.size());
    for (auto& c : checks) BOOST_CHECK(!c().has_value());
}

BOOST_AUTO_TEST_SUITE_END()
