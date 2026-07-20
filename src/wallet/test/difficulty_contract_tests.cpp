// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/difficulty_contract.h>

#include <addresstype.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/difficulty_cfd.h>
#include <key.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/transaction_identifier.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <map>
#include <optional>
#include <vector>

using namespace wallet;

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

XOnlyPubKey TestKey(unsigned char seed)
{
    std::vector<unsigned char> sk(32, 0);
    sk[31] = seed; // small non-zero scalar -> valid private key
    CKey k;
    k.Set(sk.begin(), sk.end(), /*fCompressedIn=*/true);
    BOOST_REQUIRE(k.IsValid());
    return XOnlyPubKey(k.GetPubKey());
}

uint32_t CanonicalNBits(uint64_t target) { arith_uint256 t{target}; return t.GetCompact(); }
CScript P2TR(const XOnlyPubKey& key) { return CScript() << OP_1 << ToByteVector(key); }

// A representative, valid contract: 10 TSC margin each leg, lambda 10, strike at difficulty 1e6,
// fixing at height 50, settle lock at fixing + DIFFCFD_MATURITY_DEPTH.
DifficultyContractTerms MakeTerms()
{
    DifficultyContractTerms terms;
    terms.strike_nbits = CanonicalNBits(1'000'000);
    terms.fixing_height = 50;
    terms.settle_lock_height = 50 + DIFFCFD_MATURITY_DEPTH;

    terms.long_leg.im = 1'000'000'000;
    terms.long_leg.lambda_q = 10 * (1u << 16);
    terms.long_leg.owner_key = TestKey(0x11); // long party
    terms.long_leg.cp_key = TestKey(0x22);    // short party

    terms.short_leg.im = 1'000'000'000;
    terms.short_leg.lambda_q = 10 * (1u << 16);
    terms.short_leg.owner_key = TestKey(0x22); // short party
    terms.short_leg.cp_key = TestKey(0x11);    // long party
    return terms;
}

// A fully-populated record (post-open state), with derived contract_id, NUMS internal keys, funded
// vault outpoints and an open txid.
DifficultyContractRecord MakeRecord(const uint256& salt = uint256::ONE)
{
    DifficultyContractRecord rec;
    rec.terms = MakeTerms();
    rec.salt = salt;
    rec.contract_id = ComputeDifficultyContractId(rec.terms, rec.salt);
    // v1: both vault internal keys are the fixed BIP341 NUMS point (key path provably disabled).
    rec.long_internal_key = XOnlyPubKey::NUMS_H;
    rec.short_internal_key = XOnlyPubKey::NUMS_H;
    rec.long_vault = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    rec.short_vault = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    rec.open_txid = uint256::ONE;
    return rec;
}

// SHORT-leg vault scriptPubKey for a record (NUMS internal key).
CScript ShortVaultSpk(const DifficultyContractRecord& rec)
{
    TaprootBuilder builder = CreateDifficultyVaultBuilder(rec, /*is_short=*/true, XOnlyPubKey::NUMS_H);
    BOOST_REQUIRE(builder.IsComplete());
    return GetScriptForDestination(builder.GetOutput());
}

// Build the SHORT-leg settlement via the production skeleton helper (which reconstructs the control
// block from the record), then run the assembled tx through the real interpreter with a mock
// FixingContext (given powLimit / burial maturity / anchor height). Returns SCRIPT_ERR_OK on a clean
// settlement, else the interpreter error.
ScriptError RunShortVaultSettlement(const DifficultyContractRecord& rec, uint32_t realized_nbits,
                                    const uint256& pow_limit, int maturity, int context_height)
{
    const CScript vault_spk = ShortVaultSpk(rec);

    DifficultySettlementSkeleton skel;
    std::string err;
    if (!BuildDifficultySettlementSkeleton(rec, /*is_short=*/true, realized_nbits, pow_limit, skel, err)) {
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
    fixing.nbits_by_height[rec.terms.fixing_height] = realized_nbits;

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
                               SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    TransactionSignatureChecker checker(&tx, 0, static_cast<CAmount>(rec.terms.short_leg.im),
                                        MissingDataBehavior::FAIL, &fixing);
    ScriptError serror = SCRIPT_ERR_OK;
    const bool ok = VerifyScript(CScript(), vault_spk, &tx.vin[0].scriptWitness, flags, checker, &serror);
    return ok ? SCRIPT_ERR_OK : serror;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(difficulty_contract_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(record_serialization_roundtrip)
{
    const DifficultyContractRecord rec = MakeRecord();

    DataStream ss{};
    ss << rec;
    DifficultyContractRecord back;
    ss >> back;

    BOOST_CHECK(back.contract_id == rec.contract_id);
    BOOST_CHECK(back.salt == rec.salt);
    BOOST_CHECK(back.long_internal_key == rec.long_internal_key);
    BOOST_CHECK(back.short_internal_key == rec.short_internal_key);
    BOOST_CHECK(back.long_vault == rec.long_vault);
    BOOST_CHECK(back.short_vault == rec.short_vault);
    BOOST_CHECK(back.open_txid == rec.open_txid);
    BOOST_CHECK_EQUAL(back.terms.strike_nbits, rec.terms.strike_nbits);
    BOOST_CHECK_EQUAL(back.terms.fixing_height, rec.terms.fixing_height);
    BOOST_CHECK_EQUAL(back.terms.settle_lock_height, rec.terms.settle_lock_height);
    BOOST_CHECK_EQUAL(back.terms.long_leg.im, rec.terms.long_leg.im);
    BOOST_CHECK_EQUAL(back.terms.short_leg.lambda_q, rec.terms.short_leg.lambda_q);
    BOOST_CHECK(back.terms.short_leg.owner_key == rec.terms.short_leg.owner_key);
    BOOST_CHECK(back.terms.long_leg.cp_key == rec.terms.long_leg.cp_key);

    // Convenience accessors select the right leg.
    BOOST_CHECK(rec.VaultInternalKey(/*is_short=*/true) == rec.short_internal_key);
    BOOST_CHECK(rec.VaultOutpoint(/*is_short=*/false) == rec.long_vault);
}

// The Fair-Sign adaptor points (added after v1) round-trip, including the absent-acceptor case.
BOOST_AUTO_TEST_CASE(adaptor_points_roundtrip)
{
    DifficultyContractRecord rec = MakeRecord();
    CKey kp; kp.MakeNewKey(/*fCompressed=*/true);
    CKey ka; ka.MakeNewKey(/*fCompressed=*/true);
    rec.fs_tx_adaptor_point = XOnlyPubKey(kp.GetPubKey());
    rec.counterparty_adaptor_point = XOnlyPubKey(ka.GetPubKey());
    rec.fs_context = uint256::ONE;

    DataStream ss{};
    ss << rec;
    DifficultyContractRecord back;
    ss >> back;
    BOOST_CHECK(back.fs_tx_adaptor_point == rec.fs_tx_adaptor_point);
    BOOST_REQUIRE(back.counterparty_adaptor_point.has_value());
    BOOST_CHECK(*back.counterparty_adaptor_point == *rec.counterparty_adaptor_point);
    BOOST_CHECK(back.fs_context == rec.fs_context);

    // Absent acceptor point serializes a single has_value=false byte and reloads as absent (fs_context
    // still follows it).
    rec.counterparty_adaptor_point.reset();
    DataStream ss2{};
    ss2 << rec;
    DifficultyContractRecord back2;
    ss2 >> back2;
    BOOST_CHECK(back2.fs_tx_adaptor_point == rec.fs_tx_adaptor_point);
    BOOST_CHECK(!back2.counterparty_adaptor_point.has_value());
    BOOST_CHECK(back2.fs_context == rec.fs_context);
}

// MIGRATION: a record serialized in the pre-atomic-open layout (base fields only, no trailing adaptor
// bytes) must still load, with the appended adaptor fields defaulting to null/absent.
BOOST_AUTO_TEST_CASE(legacy_record_loads_without_adaptor_fields)
{
    const DifficultyContractRecord rec = MakeRecord();

    // Reproduce the exact pre-migration byte layout: the 12 base fields only.
    DataStream legacy{};
    legacy << rec.contract_id << rec.salt << rec.terms
           << rec.long_internal_key << rec.short_internal_key
           << rec.long_vault << rec.short_vault << rec.open_txid
           << rec.long_owner_internal << rec.long_cp_internal
           << rec.short_owner_internal << rec.short_cp_internal;

    DifficultyContractRecord loaded;
    legacy >> loaded;

    BOOST_CHECK_EQUAL(legacy.size(), 0u);  // fully consumed — no trailing bytes existed
    BOOST_CHECK(loaded.contract_id == rec.contract_id);
    BOOST_CHECK(loaded.open_txid == rec.open_txid);
    BOOST_CHECK(loaded.short_cp_internal == rec.short_cp_internal);
    BOOST_CHECK(loaded.fs_tx_adaptor_point == XOnlyPubKey{});
    BOOST_CHECK(!loaded.counterparty_adaptor_point.has_value());
    BOOST_CHECK(loaded.fs_context == uint256{});
}

// The adaptor context is the proposer's OFFER COMMITMENT: deterministic, bound to econ + the proposer's
// own payout keys + side + salt, and (critically) independent of the leg payout keys carried in `terms`
// (those hold the acceptor's keys, which are unset at propose). This is what lets the proposer's
// propose-time derivation reproduce identically at ceremony.
BOOST_AUTO_TEST_CASE(offer_commitment_binding)
{
    const DifficultyContractTerms terms = MakeTerms();
    CKey ko; ko.MakeNewKey(/*fCompressed=*/true); const XOnlyPubKey owner(ko.GetPubKey());
    CKey kc; kc.MakeNewKey(/*fCompressed=*/true); const XOnlyPubKey cp(kc.GetPubKey());
    const uint256 salt = uint256::ONE;

    const uint256 base = ComputeDifficultyOfferCommitment(/*proposer_is_short=*/0, terms, owner, cp, salt);
    BOOST_CHECK(base == ComputeDifficultyOfferCommitment(0, terms, owner, cp, salt));  // deterministic

    // Independent of the leg PAYOUT keys in `terms` (acceptor's keys, unset at propose).
    DifficultyContractTerms terms_keys = terms;
    CKey kx; kx.MakeNewKey(/*fCompressed=*/true);
    terms_keys.long_leg.owner_key = XOnlyPubKey(kx.GetPubKey());
    terms_keys.short_leg.cp_key = XOnlyPubKey(kx.GetPubKey());
    BOOST_CHECK(ComputeDifficultyOfferCommitment(0, terms_keys, owner, cp, salt) == base);

    // Binds econ, side, proposer keys, and salt.
    DifficultyContractTerms terms_econ = terms;
    terms_econ.fixing_height += 1;
    BOOST_CHECK(ComputeDifficultyOfferCommitment(0, terms_econ, owner, cp, salt) != base);          // econ
    BOOST_CHECK(ComputeDifficultyOfferCommitment(1, terms, owner, cp, salt) != base);               // side
    BOOST_CHECK(ComputeDifficultyOfferCommitment(0, terms, cp, owner, salt) != base);               // proposer keys
    BOOST_CHECK(ComputeDifficultyOfferCommitment(0, terms, owner, cp, uint256::ZERO) != base);      // salt
}

// ComputeDifficultyContractMeta is the key adaptor.prepare uses to locate the contract, so it must
// change with the contract id and with EITHER adaptor point, and must distinguish an absent acceptor
// point from a present one (the has_value byte supplies that domain separation — without it, an absent
// point and a present-but-null point would collide).
BOOST_AUTO_TEST_CASE(contract_meta_binding)
{
    DifficultyContractRecord rec = MakeRecord();
    CKey kp; kp.MakeNewKey(/*fCompressed=*/true);
    CKey ka; ka.MakeNewKey(/*fCompressed=*/true);
    rec.fs_tx_adaptor_point = XOnlyPubKey(kp.GetPubKey());
    rec.counterparty_adaptor_point = XOnlyPubKey(ka.GetPubKey());

    const uint256 base = ComputeDifficultyContractMeta(rec);
    BOOST_CHECK(base == ComputeDifficultyContractMeta(rec));  // deterministic

    // contract id
    {
        DifficultyContractRecord r = rec;
        r.contract_id = ComputeDifficultyContractId(rec.terms, uint256::ZERO);  // != rec.contract_id (salt ONE)
        BOOST_CHECK(ComputeDifficultyContractMeta(r) != base);
    }
    // proposer point
    {
        DifficultyContractRecord r = rec;
        CKey k2; k2.MakeNewKey(/*fCompressed=*/true);
        r.fs_tx_adaptor_point = XOnlyPubKey(k2.GetPubKey());
        BOOST_CHECK(ComputeDifficultyContractMeta(r) != base);
    }
    // acceptor point
    {
        DifficultyContractRecord r = rec;
        CKey k2; k2.MakeNewKey(/*fCompressed=*/true);
        r.counterparty_adaptor_point = XOnlyPubKey(k2.GetPubKey());
        BOOST_CHECK(ComputeDifficultyContractMeta(r) != base);
    }
    // absent vs present acceptor point — and present-but-null still differs from absent
    {
        DifficultyContractRecord r_absent = rec;
        r_absent.counterparty_adaptor_point.reset();
        BOOST_CHECK(ComputeDifficultyContractMeta(r_absent) != base);

        DifficultyContractRecord r_present_null = rec;
        r_present_null.counterparty_adaptor_point = XOnlyPubKey{};
        BOOST_CHECK(ComputeDifficultyContractMeta(r_present_null) != ComputeDifficultyContractMeta(r_absent));
    }
}

// nBits -> tokens/sec is the human-readable representation for term sheets / pricing: positive, monotone
// in difficulty (a smaller/harder target implies more throughput), deterministic, and 0 for a bad target.
BOOST_AUTO_TEST_CASE(nbits_to_tokens_per_sec)
{
    BOOST_CHECK_EQUAL(DifficultyNBitsToTokensPerSec(0), 0.0);  // undecodable / zero target

    const double easy = DifficultyNBitsToTokensPerSec(CanonicalNBits(8'000'000));  // larger target
    const double hard = DifficultyNBitsToTokensPerSec(CanonicalNBits(2'000'000));  // smaller/harder target
    BOOST_CHECK(easy > 0.0);
    BOOST_CHECK(hard > easy);                                                       // harder => more tokens/sec
    BOOST_CHECK_EQUAL(hard, DifficultyNBitsToTokensPerSec(CanonicalNBits(2'000'000)));  // deterministic
}

// The wizard lets a human strike in tok/s; DifficultyTokensPerSecToNBits derives the canonical compact
// target. The compact encoding is lossy, so we require the REALIZED throughput (forward of the derived
// nBits) to track the requested strike tightly, plus monotonicity and the bad-input guard.
BOOST_AUTO_TEST_CASE(tokens_per_sec_to_nbits_roundtrip)
{
    BOOST_CHECK_EQUAL(DifficultyTokensPerSecToNBits(0.0), 0u);   // non-positive => 0
    BOOST_CHECK_EQUAL(DifficultyTokensPerSecToNBits(-5.0), 0u);

    for (double tps : {1.0e6, 5.0e8, 1.0e9, 7.5e9, 1.0e12, 3.3e13}) {
        const uint32_t nbits = DifficultyTokensPerSecToNBits(tps);
        BOOST_CHECK(nbits != 0);
        const double realized = DifficultyNBitsToTokensPerSec(nbits);
        BOOST_CHECK(realized > 0.0);
        BOOST_CHECK_CLOSE(realized, tps, /*tolerance_percent=*/0.5);  // lossy compact, but tight
    }

    // A higher tok/s strike implies a harder target => more realized throughput.
    const uint32_t lo = DifficultyTokensPerSecToNBits(1.0e9);
    const uint32_t hi = DifficultyTokensPerSecToNBits(1.0e12);
    BOOST_CHECK(DifficultyNBitsToTokensPerSec(hi) > DifficultyNBitsToTokensPerSec(lo));

    // nBits -> tok/s -> nBits' is realized-consistent for a canonical chain target.
    const uint32_t n0 = CanonicalNBits(4'000'000);
    const double t0 = DifficultyNBitsToTokensPerSec(n0);
    BOOST_CHECK_CLOSE(DifficultyNBitsToTokensPerSec(DifficultyTokensPerSecToNBits(t0)), t0, 0.5);
}

// The adaptor KDF is deterministic and bound to salt, context, and role: a reused (owner key, salt)
// cannot repeat the secret across contracts (context) or sides (role), and point == secret·G.
BOOST_AUTO_TEST_CASE(derive_fs_adaptor_binding)
{
    CKey owner; owner.MakeNewKey(/*fCompressed=*/true);
    const uint256 ctxA = ComputeDifficultyContractId(MakeTerms(), uint256::ONE);
    const uint256 ctxB = ComputeDifficultyContractId(MakeTerms(), uint256::ZERO);
    const uint256 saltA = uint256::ONE;
    const uint256 saltB = uint256::ZERO;

    const auto [s1, p1] = DeriveDifficultyFsAdaptor(owner, saltA, ctxA, DIFFICULTY_FS_ROLE_PROPOSER);
    const auto [s2, p2] = DeriveDifficultyFsAdaptor(owner, saltA, ctxA, DIFFICULTY_FS_ROLE_PROPOSER);
    BOOST_CHECK(s1 == s2);          // deterministic
    BOOST_CHECK(p1 == p2);

    // point == secret·G
    CKey ks; ks.Set(s1.begin(), s1.end(), /*fCompressed=*/true);
    BOOST_REQUIRE(ks.IsValid());
    BOOST_CHECK(XOnlyPubKey(ks.GetPubKey()) == p1);

    // Sensitive to role, context, and salt (each independently must change the secret).
    BOOST_CHECK(std::get<0>(DeriveDifficultyFsAdaptor(owner, saltA, ctxA, DIFFICULTY_FS_ROLE_ACCEPTOR)) != s1);
    BOOST_CHECK(std::get<0>(DeriveDifficultyFsAdaptor(owner, saltA, ctxB, DIFFICULTY_FS_ROLE_PROPOSER)) != s1);
    BOOST_CHECK(std::get<0>(DeriveDifficultyFsAdaptor(owner, saltB, ctxA, DIFFICULTY_FS_ROLE_PROPOSER)) != s1);
}

// contract_id binds to terms AND salt, so economically-identical trades get distinct record ids.
BOOST_AUTO_TEST_CASE(contract_id_salt_disambiguation)
{
    const DifficultyContractTerms terms = MakeTerms();
    BOOST_CHECK(ComputeDifficultyContractId(terms, uint256::ONE) != ComputeDifficultyContractId(terms, uint256::ZERO));
    BOOST_CHECK(ComputeDifficultyContractId(terms, uint256::ONE) == ComputeDifficultyContractId(terms, uint256::ONE)); // deterministic

    DifficultyContractTerms other = terms;
    other.strike_nbits = CanonicalNBits(2'000'000);
    BOOST_CHECK(ComputeDifficultyContractId(terms, uint256::ONE) != ComputeDifficultyContractId(other, uint256::ONE)); // binds to terms
}

// Vault output-key uniqueness comes from the committed leaf via the BIP341 taptweak, NOT from the
// internal key: with the SAME NUMS_H internal key, distinct legs / terms produce distinct output keys
// (so v1 never needs a bespoke per-contract internal key, which could not be argued unspendable).
BOOST_AUTO_TEST_CASE(distinct_vault_output_keys_from_taptweak)
{
    const DifficultyContractRecord rec = MakeRecord(uint256::ONE);
    TaprootBuilder long_b = CreateDifficultyVaultBuilder(rec, /*is_short=*/false, XOnlyPubKey::NUMS_H);
    TaprootBuilder short_b = CreateDifficultyVaultBuilder(rec, /*is_short=*/true, XOnlyPubKey::NUMS_H);
    BOOST_REQUIRE(long_b.IsComplete() && short_b.IsComplete());

    // Same NUMS_H internal key, different committed leaf (long vs short) -> different output key.
    BOOST_CHECK(!(long_b.GetOutput() == short_b.GetOutput()));

    // REGRESSION GUARD: SAME terms, DIFFERENT salt -> different contract_id, committed in the leaf ->
    // different output key. Without the contract_id commitment these two vaults would collide.
    const DifficultyContractRecord rec_other_salt = MakeRecord(uint256::ZERO); // same terms, different salt
    BOOST_REQUIRE(rec.contract_id != rec_other_salt.contract_id);
    TaprootBuilder long_b_salt = CreateDifficultyVaultBuilder(rec_other_salt, /*is_short=*/false, XOnlyPubKey::NUMS_H);
    BOOST_REQUIRE(long_b_salt.IsComplete());
    BOOST_CHECK(!(long_b.GetOutput() == long_b_salt.GetOutput()));

    // Different contract terms (strike) -> different leaf -> different output key.
    DifficultyContractRecord rec_other_terms = MakeRecord(uint256::ONE);
    rec_other_terms.terms.strike_nbits = CanonicalNBits(2'000'000);
    rec_other_terms.contract_id = ComputeDifficultyContractId(rec_other_terms.terms, rec_other_terms.salt);
    TaprootBuilder long_b_terms = CreateDifficultyVaultBuilder(rec_other_terms, /*is_short=*/false, XOnlyPubKey::NUMS_H);
    BOOST_REQUIRE(long_b_terms.IsComplete());
    BOOST_CHECK(!(long_b.GetOutput() == long_b_terms.GetOutput()));
}

// DB persistence: a registered record survives a wallet reload (Write -> LoadWallet -> Find).
BOOST_AUTO_TEST_CASE(db_persistence_roundtrip)
{
    const DifficultyContractRecord rec = MakeRecord();
    m_wallet.RegisterDifficultyContract(rec); // in-memory + WalletBatch write-through
    BOOST_REQUIRE(m_wallet.FindDifficultyContract(rec.contract_id).has_value());

    // Reload a fresh wallet from a duplicate of the on-disk database.
    std::unique_ptr<WalletDatabase> db = DuplicateMockDatabase(m_wallet.GetDatabase());
    CWallet reloaded(m_node.chain.get(), "", std::move(db));
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);

    const auto found = reloaded.FindDifficultyContract(rec.contract_id);
    BOOST_REQUIRE(found.has_value());
    BOOST_CHECK(found->salt == rec.salt);
    BOOST_CHECK(found->long_vault == rec.long_vault);
    BOOST_CHECK(found->short_vault == rec.short_vault);
    BOOST_CHECK(found->open_txid == rec.open_txid);
    BOOST_CHECK(found->long_internal_key == rec.long_internal_key);
    BOOST_CHECK(found->short_internal_key == rec.short_internal_key);
    BOOST_CHECK_EQUAL(found->terms.strike_nbits, rec.terms.strike_nbits);
    BOOST_CHECK_EQUAL(found->terms.short_leg.im, rec.terms.short_leg.im);
}

BOOST_AUTO_TEST_CASE(terms_validation)
{
    std::string err;
    BOOST_CHECK(MakeTerms().Validate(err));

    DifficultyContractTerms zero_lambda = MakeTerms();
    zero_lambda.short_leg.lambda_q = 0;
    BOOST_CHECK(!zero_lambda.Validate(err));

    DifficultyContractTerms tiny_im = MakeTerms();
    tiny_im.long_leg.im = MIN_SETTLE_OUTPUT - 1;
    BOOST_CHECK(!tiny_im.Validate(err));

    DifficultyContractTerms asset_im = MakeTerms();
    asset_im.long_leg.im_asset = uint256::ONE; // non-native -> rejected in v1
    BOOST_CHECK(!asset_im.Validate(err));

    DifficultyContractTerms bad_strike = MakeTerms();
    bad_strike.strike_nbits = 0x03001234; // decodes to 0x1234 but normalizes to 0x02123400
    BOOST_CHECK(!bad_strike.Validate(err));

    DifficultyContractTerms early_lock = MakeTerms();
    early_lock.settle_lock_height = early_lock.fixing_height + DIFFCFD_MATURITY_DEPTH - 1;
    BOOST_CHECK(!early_lock.Validate(err));

    // fixing_height beyond the consensus int range is rejected.
    DifficultyContractTerms huge_fixing = MakeTerms();
    huge_fixing.fixing_height = static_cast<uint32_t>(std::numeric_limits<int>::max()) + 1u;
    BOOST_CHECK(!huge_fixing.Validate(err));

    // powLimit: a canonical strike that decodes ABOVE the chain powLimit passes the bare check but is
    // rejected by the powLimit-aware overload (it would be unspendable on-chain).
    DifficultyContractTerms strike_terms = MakeTerms(); // strike target == 1,000,000 (canonical)
    BOOST_CHECK(strike_terms.Validate(err)); // no powLimit
    const uint256 tiny_powlimit = ArithToUint256(arith_uint256{100}); // max target 100 < 1,000,000
    BOOST_CHECK(!strike_terms.Validate(err, &tiny_powlimit));
    const uint256 ample_powlimit = ArithToUint256(arith_uint256{2'000'000});
    BOOST_CHECK(strike_terms.Validate(err, &ample_powlimit));
}

// OPTION invariants: exactly one margined writer leg + a non-zero premium; the non-writer leg must be
// empty; a CFD must not carry a premium; and kind/premium are committed in contract_id.
BOOST_AUTO_TEST_CASE(option_terms_validation)
{
    std::string err;
    // A valid OPTION = a CFD with the non-writer (short) leg emptied + a premium added (writer = long).
    auto make_option = []() {
        DifficultyContractTerms t = MakeTerms();
        t.kind = DIFFICULTY_KIND_OPTION;
        t.premium = 100'000'000;
        t.short_leg = DifficultyLegTerms{}; // empty non-writer leg
        return t;
    };
    BOOST_CHECK(make_option().Validate(err));

    // A CFD must NOT carry a premium.
    DifficultyContractTerms cfd_premium = MakeTerms();
    cfd_premium.premium = 1;
    BOOST_CHECK(!cfd_premium.Validate(err));

    // Option premium must be >= dust, and non-zero.
    DifficultyContractTerms tiny_prem = make_option();
    tiny_prem.premium = MIN_SETTLE_OUTPUT - 1;
    BOOST_CHECK(!tiny_prem.Validate(err));
    DifficultyContractTerms no_prem = make_option();
    no_prem.premium = 0;
    BOOST_CHECK(!no_prem.Validate(err));

    // Exactly ONE writer leg: both legs active (CFD shape) is rejected, as is zero active legs.
    DifficultyContractTerms both_active = MakeTerms();
    both_active.kind = DIFFICULTY_KIND_OPTION;
    both_active.premium = 100'000'000;
    BOOST_CHECK(!both_active.Validate(err));
    DifficultyContractTerms none_active = make_option();
    none_active.long_leg = DifficultyLegTerms{};
    BOOST_CHECK(!none_active.Validate(err));

    // The non-writer leg must be fully empty — a stray key on the short leg is rejected.
    DifficultyContractTerms dirty_other = make_option();
    dirty_other.short_leg.cp_key = TestKey(0x33);
    BOOST_CHECK(!dirty_other.Validate(err));

    // contract_id is sensitive to kind and to premium.
    const uint256 salt = uint256::ONE;
    BOOST_CHECK(ComputeDifficultyContractId(MakeTerms(), salt) != ComputeDifficultyContractId(make_option(), salt));
    DifficultyContractTerms other_prem = make_option();
    other_prem.premium = 200'000'000;
    BOOST_CHECK(ComputeDifficultyContractId(make_option(), salt) != ComputeDifficultyContractId(other_prem, salt));
}

// CRUX: a vault built by the wallet helper settles correctly through the REAL interpreter — the leaf
// bytes are opcode-compatible, the Taproot commitment is valid, CLTV passes, and the committed payout
// keys/amounts match what OP_DIFFCFD_SETTLE computes. Proves Slice 2 dovetails with Slice 1.
BOOST_AUTO_TEST_CASE(vault_leaf_settles_through_consensus)
{
    const DifficultyContractRecord rec = MakeRecord(); // fixing 50, lock 150
    std::string err;
    BOOST_REQUIRE(rec.terms.Validate(err));

    // Wide powLimit + maturity 0: proves leaf byte-compatibility + commitment + CLTV + settle/output match.
    const ScriptError res = RunShortVaultSettlement(rec, /*realized=*/CanonicalNBits(950'000),
                                                    /*pow_limit=*/ArithToUint256(~arith_uint256{0}),
                                                    /*maturity=*/0, /*context_height=*/rec.terms.fixing_height + 1);
    BOOST_CHECK_MESSAGE(res == SCRIPT_ERR_OK, "VerifyScript failed: " << ScriptErrorString(res));
}

// Production semantics: the chain's real powLimit AND the consensus burial maturity, at the exact
// boundary. Settlement succeeds when the fixing is matured H == anchor - DIFFCFD_MATURITY_DEPTH, and
// fails (DIFFCFD_HEIGHT) one block too recent.
BOOST_AUTO_TEST_CASE(vault_settles_real_powlimit_and_maturity_boundary)
{
    DifficultyContractRecord rec = MakeRecord();
    rec.terms.fixing_height = 200;
    rec.terms.settle_lock_height = 200 + DIFFCFD_MATURITY_DEPTH;
    rec.contract_id = ComputeDifficultyContractId(rec.terms, rec.salt); // terms changed -> recompute id

    const uint256 powlim = Params().GetConsensus().powLimit; // real chain powLimit (not ~0)
    std::string err;
    BOOST_REQUIRE(rec.terms.Validate(err, &powlim)); // strike within the real powLimit

    const uint32_t realized = CanonicalNBits(950'000);

    // Exact maturity boundary: anchor = fixing + DIFFCFD_MATURITY_DEPTH => H == anchor - depth (resolvable).
    BOOST_CHECK_EQUAL(RunShortVaultSettlement(rec, realized, powlim, DIFFCFD_MATURITY_DEPTH,
                                              /*context_height=*/rec.terms.fixing_height + DIFFCFD_MATURITY_DEPTH),
                      SCRIPT_ERR_OK);

    // One block too recent: anchor = fixing + depth - 1 => H > anchor - depth => not yet buried.
    BOOST_CHECK_EQUAL(RunShortVaultSettlement(rec, realized, powlim, DIFFCFD_MATURITY_DEPTH,
                                              /*context_height=*/rec.terms.fixing_height + DIFFCFD_MATURITY_DEPTH - 1),
                      SCRIPT_ERR_DIFFCFD_HEIGHT);
}

// The settlement skeleton encodes the keeper constraints: one vault input with a no-signature
// witness, a non-final sequence, nLockTime == settle_lock_height, and exact output-conserved covenant
// payouts that skip a zero leg exactly like the covenant.
BOOST_AUTO_TEST_CASE(settlement_skeleton_shapes)
{
    const DifficultyContractRecord rec = MakeRecord();
    const uint256 powlim = ArithToUint256(~arith_uint256{0});

    const CScript leaf = BuildDifficultyLeafScript(rec, /*is_short=*/true);
    const std::vector<unsigned char> leafvec(leaf.begin(), leaf.end());

    auto build = [&](uint32_t realized, DifficultySettlementSkeleton& skel) {
        std::string err;
        return BuildDifficultySettlementSkeleton(rec, /*is_short=*/true, realized, powlim, skel, err);
    };

    // Partial loss -> two outputs, output-conserved (sum == im), keeper-shaped witness/sequence/locktime.
    DifficultySettlementSkeleton partial;
    BOOST_REQUIRE(build(CanonicalNBits(950'000), partial));
    BOOST_REQUIRE_EQUAL(partial.payouts.size(), 2u);
    BOOST_CHECK(partial.payout.payout_owner > 0 && partial.payout.payout_cp > 0);
    BOOST_CHECK_EQUAL(partial.payouts[0].nValue + partial.payouts[1].nValue, rec.terms.short_leg.im);
    BOOST_CHECK_EQUAL(partial.nlocktime, rec.terms.settle_lock_height);
    BOOST_CHECK(partial.vault_input.nSequence != CTxIn::SEQUENCE_FINAL);
    BOOST_CHECK(partial.vault_input.prevout == rec.VaultOutpoint(/*is_short=*/true)); // from the record
    BOOST_REQUIRE_EQUAL(partial.vault_input.scriptWitness.stack.size(), 2u); // [leaf, control], no signature
    BOOST_CHECK(partial.vault_input.scriptWitness.stack[0] == leafvec); // committed leaf (with contract_id prefix)
    BOOST_CHECK(partial.payouts[0].scriptPubKey == P2TR(rec.terms.short_leg.owner_key));
    BOOST_CHECK(partial.payouts[1].scriptPubKey == P2TR(rec.terms.short_leg.cp_key));

    // Deep adverse move -> full liquidation: single cp output == im, owner leg skipped.
    DifficultySettlementSkeleton liq;
    BOOST_REQUIRE(build(CanonicalNBits(800'000), liq));
    BOOST_REQUIRE_EQUAL(liq.payouts.size(), 1u);
    BOOST_CHECK_EQUAL(liq.payout.payout_owner, 0u);
    BOOST_CHECK_EQUAL(liq.payouts[0].nValue, rec.terms.short_leg.im);
    BOOST_CHECK(liq.payouts[0].scriptPubKey == P2TR(rec.terms.short_leg.cp_key));

    // Favorable/flat for short (realized target above strike => difficulty fell => short in-the-money):
    // single owner output == im, cp leg skipped.
    DifficultySettlementSkeleton flat;
    BOOST_REQUIRE(build(CanonicalNBits(1'100'000), flat));
    BOOST_REQUIRE_EQUAL(flat.payouts.size(), 1u);
    BOOST_CHECK_EQUAL(flat.payout.payout_cp, 0u);
    BOOST_CHECK_EQUAL(flat.payouts[0].nValue, rec.terms.short_leg.im);
    BOOST_CHECK(flat.payouts[0].scriptPubKey == P2TR(rec.terms.short_leg.owner_key));

    // Out-of-range strike/realized for a tiny powLimit -> rejected (mirrors the consensus range check).
    DifficultySettlementSkeleton bad;
    std::string err;
    const uint256 tiny = ArithToUint256(arith_uint256{100});
    BOOST_CHECK(!BuildDifficultySettlementSkeleton(rec, /*is_short=*/true, CanonicalNBits(950'000), tiny, bad, err));
}

BOOST_AUTO_TEST_SUITE_END()
