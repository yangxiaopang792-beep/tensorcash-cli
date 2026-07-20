// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Validation-level tests for the difficulty covenant: the CONSENSUS one-difficulty-input rule and
// the chain-difficulty-read cache bypass (DIFFICULTY_DERIVATIVE.md §2.3 / §3.3), driven through the real
// CheckInputScripts (the same function ConnectBlock and the mempool call). CheckInputScripts does
// NOT check coinbase maturity (that is CheckTxInputs), so we spend fabricated taproot UTXOs added to
// a scratch coins view layered on the active tip.

#include <arith_uint256.h>
#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/difficulty_cfd.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <crypto/common.h>
#include <key.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <optional>
#include <vector>

// Production CheckInputScripts (redeclared as in txvalidationcache_tests.cpp), with the difficulty
// fixing resolver parameter.
bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks,
                       const FixingContext* fixing) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_FIXTURE_TEST_SUITE(difficulty_cfd_validation_tests, TestChain100Setup)

namespace {

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

std::vector<unsigned char> LE32(uint32_t v) { std::vector<unsigned char> b(4); WriteLE32(b.data(), v); return b; }
std::vector<unsigned char> LE64(uint64_t v) { std::vector<unsigned char> b(8); WriteLE64(b.data(), v); return b; }
std::vector<unsigned char> Key(unsigned char fill) { return std::vector<unsigned char>(32, fill); }
CScript P2TR(const std::vector<unsigned char>& k) { return CScript() << OP_1 << k; }
uint32_t CanonicalNBits(uint64_t target) { arith_uint256 t{target}; return t.GetCompact(); }

CScript BuildLeaf(uint32_t H, uint32_t strike_nbits, uint32_t lambda_q, uint8_t dir, uint64_t vault_im,
                  const std::vector<unsigned char>& owner_key, const std::vector<unsigned char>& cp_key)
{
    CScript s;
    s << LE32(H); // fixing_height operand; OP_DIFFCFD_SETTLE resolves realized nBits @ H itself
    s << LE32(strike_nbits);
    s << LE32(lambda_q);
    s << std::vector<unsigned char>{dir};
    s << LE64(vault_im);
    s << owner_key;
    s << cp_key;
    s << OP_DIFFCFD_SETTLE;
    return s;
}

// A well-formed (but commitment-bogus) v1 control block: 33 bytes, leaf version 0xc0. Enough for the
// witness PRE-SCAN to recognise a revealed v1 tapscript leaf; the commitment itself is never checked
// because the pre-scan rejects (one-input rule) before any script execution.
std::vector<unsigned char> BogusControl()
{
    std::vector<unsigned char> c(TAPROOT_CONTROL_BASE_SIZE, 0x00);
    c[0] = TAPROOT_LEAF_TAPSCRIPT;
    return c;
}

Txid FakeTxid(unsigned char fill) { uint256 h; std::memset(h.data(), fill, h.size()); return Txid::FromUint256(h); }

constexpr int H = 50;
constexpr uint32_t LAMBDA10 = 10 * static_cast<uint32_t>(DIFFCFD_LAMBDA_SCALE);
constexpr uint64_t IM = 1'000'000'000;

} // namespace

// CONSENSUS one-difficulty-input rule: a tx with two inputs each revealing a leaf containing
// OP_DIFFCFD_SETTLE is rejected with bad-txns-diffcfd-multiple-inputs, before any script execution.
BOOST_AUTO_TEST_CASE(rejects_two_difficulty_inputs)
{
    LOCK(cs_main);
    CCoinsViewCache view(&m_node.chainman->ActiveChainstate().CoinsTip());

    const CScript leaf = BuildLeaf(H, CanonicalNBits(1'000'000), LAMBDA10, 0x01, IM, Key(0xA1), Key(0xB2));
    const std::vector<unsigned char> leafvec(leaf.begin(), leaf.end());

    CMutableTransaction mtx;
    for (unsigned char i = 0; i < 2; ++i) {
        const COutPoint op{FakeTxid(0x10 + i), 0};
        view.AddCoin(op, Coin(CTxOut(static_cast<CAmount>(IM), P2TR(Key(0x30 + i))), 1, false), false);
        CTxIn in(op);
        in.scriptWitness.stack = {leafvec, BogusControl()};
        mtx.vin.push_back(in);
    }
    mtx.vout.emplace_back(CAmount{1000}, P2TR(Key(0xCC)));

    TxValidationState state;
    PrecomputedTransactionData txdata;
    const bool ok = CheckInputScripts(CTransaction(mtx), state, view,
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT,
                                      true, true, txdata, m_node.chainman->m_validation_cache, nullptr, nullptr);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-diffcfd-multiple-inputs");
}

// The pre-scan uses GetOp: a 0xbe byte inside a pushdata is NOT counted as OP_DIFFCFD_SETTLE.
// One real difficulty leaf + one "<0xbe> OP_DROP OP_TRUE" leaf => count 1 => NOT the multi-input
// rejection (it later fails the bogus taproot commitment for a different reason).
BOOST_AUTO_TEST_CASE(pushdata_byte_not_counted)
{
    LOCK(cs_main);
    CCoinsViewCache view(&m_node.chainman->ActiveChainstate().CoinsTip());

    const CScript real_leaf = BuildLeaf(H, CanonicalNBits(1'000'000), LAMBDA10, 0x01, IM, Key(0xA1), Key(0xB2));
    const std::vector<unsigned char> real_vec(real_leaf.begin(), real_leaf.end());

    CScript pushdata_leaf;
    pushdata_leaf << std::vector<unsigned char>{static_cast<unsigned char>(OP_DIFFCFD_SETTLE)} << OP_DROP << OP_TRUE;
    const std::vector<unsigned char> push_vec(pushdata_leaf.begin(), pushdata_leaf.end());

    CMutableTransaction mtx;
    const COutPoint op0{FakeTxid(0x21), 0};
    view.AddCoin(op0, Coin(CTxOut(static_cast<CAmount>(IM), P2TR(Key(0x41))), 1, false), false);
    CTxIn in0(op0); in0.scriptWitness.stack = {real_vec, BogusControl()}; mtx.vin.push_back(in0);

    const COutPoint op1{FakeTxid(0x22), 0};
    view.AddCoin(op1, Coin(CTxOut(static_cast<CAmount>(IM), P2TR(Key(0x42))), 1, false), false);
    CTxIn in1(op1); in1.scriptWitness.stack = {push_vec, BogusControl()}; mtx.vin.push_back(in1);

    mtx.vout.emplace_back(CAmount{1000}, P2TR(Key(0xCC)));

    TxValidationState state;
    PrecomputedTransactionData txdata;
    const bool ok = CheckInputScripts(CTransaction(mtx), state, view,
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT,
                                      true, true, txdata, m_node.chainman->m_validation_cache, nullptr, nullptr);
    BOOST_CHECK(!ok); // fails on the bogus commitment of input 0, NOT the one-input rule
    BOOST_CHECK(state.GetRejectReason() != "bad-txns-diffcfd-multiple-inputs");
}

// Reading chain difficulty (OP_DIFFCFD_SETTLE resolves nBits @ H, as does OP_NBITS_AT) makes a tx
// non-cacheable: a valid difficulty spend must NOT be served from / stored in the tx-level script
// cache. We build a real Taproot vault so the spend actually passes, then assert
// a second CheckInputScripts call still produces per-input checks (i.e. was re-validated, not cached).
BOOST_AUTO_TEST_CASE(chain_difficulty_read_tx_not_cached)
{
    LOCK(cs_main);
    CCoinsViewCache view(&m_node.chainman->ActiveChainstate().CoinsTip());

    const auto owner = Key(0xA1), cp = Key(0xB2);
    const uint32_t strike_nbits = CanonicalNBits(1'000'000);
    const uint32_t realized_nbits = CanonicalNBits(950'000); // short leg, partial loss
    const uint256 powlim = ArithToUint256(~arith_uint256{0});
    const auto K = DeriveTarget(strike_nbits, powlim);
    const auto S = DeriveTarget(realized_nbits, powlim);
    BOOST_REQUIRE(K && S);
    DiffCfdPayout payout;
    BOOST_REQUIRE(ComputeDiffCfdPayout(*K, *S, LAMBDA10, IM, /*short=*/true, payout));
    BOOST_REQUIRE(payout.payout_owner > 0 && payout.payout_cp > 0);

    const CScript leaf = BuildLeaf(H, strike_nbits, LAMBDA10, 0x01, IM, owner, cp);
    const std::vector<unsigned char> leafvec(leaf.begin(), leaf.end());

    // Real Taproot output committing to the leaf, so VerifyWitnessProgram accepts the control block.
    unsigned char seckey[32]; std::memset(seckey, 0x01, sizeof(seckey));
    CKey key; key.Set(seckey, seckey + 32, /*fCompressedIn=*/true);
    BOOST_REQUIRE(key.IsValid());
    const XOnlyPubKey internal(key.GetPubKey());

    TaprootBuilder builder;
    builder.Add(0, leafvec, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(internal);
    BOOST_REQUIRE(builder.IsComplete());
    const CScript spk = GetScriptForDestination(builder.GetOutput());

    const TaprootSpendData spend = builder.GetSpendData();
    auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    BOOST_REQUIRE(it != spend.scripts.end() && !it->second.empty());
    const std::vector<unsigned char> control = *it->second.begin();

    const COutPoint vault{FakeTxid(0x55), 0};
    view.AddCoin(vault, Coin(CTxOut(static_cast<CAmount>(IM), spk), 1, false), false);

    CMutableTransaction mtx;
    CTxIn in(vault); in.scriptWitness.stack = {leafvec, control}; mtx.vin.push_back(in);
    mtx.vout.emplace_back(static_cast<CAmount>(payout.payout_owner), P2TR(owner));
    mtx.vout.emplace_back(static_cast<CAmount>(payout.payout_cp), P2TR(cp));
    const CTransaction tx{mtx};

    MockFixingContext fixing;
    fixing.context_height = H + 1;
    fixing.nbits_by_height[H] = realized_nbits;

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT;

    // First call: executes inline, must PASS (end-to-end valid difficulty settlement), and must NOT
    // store in the script cache because the leaf reads chain difficulty (OP_DIFFCFD_SETTLE).
    TxValidationState state1;
    PrecomputedTransactionData txdata1;
    BOOST_CHECK(CheckInputScripts(tx, state1, view, flags, true, /*cacheFullScriptStore=*/true,
                                  txdata1, m_node.chainman->m_validation_cache, nullptr, &fixing));

    // Second call with pvChecks: if the tx had been cached, the cache hit would short-circuit and
    // leave checks empty. With the bypass it is re-validated, so one check per input is produced.
    TxValidationState state2;
    PrecomputedTransactionData txdata2;
    std::vector<CScriptCheck> checks;
    BOOST_CHECK(CheckInputScripts(tx, state2, view, flags, true, true,
                                  txdata2, m_node.chainman->m_validation_cache, &checks, &fixing));
    BOOST_CHECK_EQUAL(checks.size(), tx.vin.size());

    // And the queued checks themselves pass when run.
    for (auto& c : checks) BOOST_CHECK(!c().has_value());
}

// BLOCK-LEVEL: the one-difficulty-input rule maps to a BLOCK consensus failure. We fund two real
// Taproot vault UTXOs, build a block whose settlement tx spends both via OP_DIFFCFD_SETTLE leaves,
// and run it through TestBlockValidity (CheckBlock + ContextualCheckBlock + ConnectBlock). The block
// is rejected with bad-txns-diffcfd-multiple-inputs and the active tip is unchanged.
BOOST_AUTO_TEST_CASE(block_with_two_difficulty_inputs_invalid)
{
    const CScript coinbase_spk = CScript() << OP_TRUE;

    // Fund two P2TR vault UTXOs by spending a mature coinbase (50 BTC -> 20 + 20, rest is fee).
    const CScript vault0 = P2TR(Key(0x71));
    const CScript vault1 = P2TR(Key(0x72));
    auto [funding, fee] = CreateValidTransaction(
        {m_coinbase_txns[0]}, {COutPoint(m_coinbase_txns[0]->GetHash(), 0)},
        /*input_height=*/1, {coinbaseKey},
        {CTxOut(20 * COIN, vault0), CTxOut(20 * COIN, vault1)},
        /*feerate=*/std::nullopt, /*fee_output=*/std::nullopt);
    CreateAndProcessBlock({funding}, coinbase_spk); // mine the funding tx -> vaults become UTXOs

    // Settlement tx spending BOTH vaults, each revealing a leaf containing OP_DIFFCFD_SETTLE.
    const CScript leaf = BuildLeaf(50, CanonicalNBits(1'000'000), LAMBDA10, 0x01, IM, Key(0xA1), Key(0xB2));
    const std::vector<unsigned char> leafvec(leaf.begin(), leaf.end());
    const Txid ftxid = CTransaction(funding).GetHash();
    CMutableTransaction settle;
    for (uint32_t n = 0; n < 2; ++n) {
        CTxIn in(COutPoint(ftxid, n));
        in.scriptWitness.stack = {leafvec, BogusControl()};
        settle.vin.push_back(in);
    }
    settle.vout.emplace_back(1 * COIN, P2TR(Key(0xCC)));

    Chainstate& chainstate = m_node.chainman->ActiveChainstate();
    const CBlock block = CreateBlock({settle}, coinbase_spk, chainstate); // assembles + solves PoW (no validation)

    LOCK(cs_main);
    CBlockIndex* tip = chainstate.m_chain.Tip();
    const uint256 tip_hash = tip->GetBlockHash();

    BlockValidationState state;
    const bool ok = TestBlockValidity(state, Params(), chainstate, block, tip,
                                      /*fCheckApi=*/false, /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-diffcfd-multiple-inputs");
    BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), tip_hash); // TestBlockValidity does not connect
}

BOOST_AUTO_TEST_SUITE_END()
