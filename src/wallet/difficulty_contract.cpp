// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/difficulty_contract.h>

#include <arith_uint256.h>
#include <consensus/difficulty_cfd.h> // MIN_SETTLE_OUTPUT, DIFFCFD_MATURITY_DEPTH
#include <crypto/common.h>            // WriteLE32 / WriteLE64
#include <hash.h>                     // HashWriter, TaggedHash
#include <key.h>                      // CKey (DeriveDifficultyFsAdaptor)
#include <pow.h>                      // DeriveTarget
#include <script/interpreter.h>       // TAPROOT_LEAF_TAPSCRIPT
#include <script/script.h>            // LOCKTIME_THRESHOLD
#include <span.h>                     // Span / MakeByteSpan
#include <tinyformat.h>
#include <util/check.h>               // Assume

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace wallet {

namespace {
std::vector<unsigned char> LE32(uint32_t v) { std::vector<unsigned char> b(4); WriteLE32(b.data(), v); return b; }
std::vector<unsigned char> LE64(uint64_t v) { std::vector<unsigned char> b(8); WriteLE64(b.data(), v); return b; }

//! A compact target is canonical iff it decodes to a positive, non-overflowing value that
//! re-encodes to the same compact (the consensus opcode requires a canonical strike).
bool IsCanonicalNBits(uint32_t nbits)
{
    arith_uint256 t;
    bool negative = false, overflow = false;
    t.SetCompact(nbits, &negative, &overflow);
    if (negative || overflow || t == 0) return false;
    return t.GetCompact() == nbits;
}

//! Exact P2TR scriptPubKey (OP_1 <xonly>) the covenant matches byte-for-byte.
CScript P2TR(const XOnlyPubKey& key) { return CScript() << OP_1 << ToByteVector(key); }
} // namespace

bool DifficultyContractTerms::Validate(std::string& err, const uint256* pow_limit) const
{
    auto check_leg = [&](const DifficultyLegTerms& leg, const char* name) -> bool {
        if (!leg.im_asset.IsNull()) { err = strprintf("%s: non-native IM is not supported in v1", name); return false; }
        if (leg.lambda_q == 0) { err = strprintf("%s: lambda_q must be non-zero", name); return false; }
        if (leg.im < MIN_SETTLE_OUTPUT) { err = strprintf("%s: im (%d) below MIN_SETTLE_OUTPUT (%d)", name, leg.im, MIN_SETTLE_OUTPUT); return false; }
        if (!leg.owner_key.IsFullyValid()) { err = strprintf("%s: owner_key is not a valid x-only key", name); return false; }
        if (!leg.cp_key.IsFullyValid()) { err = strprintf("%s: cp_key is not a valid x-only key", name); return false; }
        return true;
    };
    auto leg_is_empty = [](const DifficultyLegTerms& leg) -> bool {
        return leg.im == 0 && leg.lambda_q == 0 && leg.im_asset.IsNull()
            && !leg.owner_key.IsFullyValid() && !leg.cp_key.IsFullyValid();
    };
    if (kind == DIFFICULTY_KIND_CFD) {
        if (premium != 0) { err = "a CFD must not carry a premium"; return false; }
        if (!check_leg(long_leg, "long_leg")) return false;
        if (!check_leg(short_leg, "short_leg")) return false;
    } else if (kind == DIFFICULTY_KIND_OPTION) {
        // Exactly ONE leg is the writer's (margined); the other must be fully empty. The buyer posts no
        // vault — they pay the premium at open instead.
        const bool long_active = !leg_is_empty(long_leg);
        const bool short_active = !leg_is_empty(short_leg);
        if (long_active == short_active) { err = "an option must fund exactly one (writer) leg"; return false; }
        if (!check_leg(long_active ? long_leg : short_leg, "writer_leg")) return false;
        if (!leg_is_empty(long_active ? short_leg : long_leg)) { err = "an option's non-writer leg must be empty"; return false; }
        if (premium < MIN_SETTLE_OUTPUT) { err = strprintf("option premium (%d) below MIN_SETTLE_OUTPUT (%d)", premium, MIN_SETTLE_OUTPUT); return false; }
    } else {
        err = strprintf("unknown contract kind %d", kind);
        return false;
    }

    if (!IsCanonicalNBits(strike_nbits)) { err = "strike_nbits is not a canonical compact target"; return false; }
    // Mirror the consensus range check: the strike must decode within the chain's powLimit (a
    // canonical-but-above-powLimit strike is otherwise unspendable on-chain).
    if (pow_limit != nullptr && !DeriveTarget(strike_nbits, *pow_limit).has_value()) {
        err = "strike_nbits is out of range for the chain powLimit";
        return false;
    }

    // OP_NBITS_AT / OP_DIFFCFD_SETTLE range-check the fixing height to a valid int before GetAncestor.
    if (fixing_height > static_cast<uint32_t>(std::numeric_limits<int>::max())) {
        err = "fixing_height exceeds the consensus int range";
        return false;
    }
    // Block-height CLTV semantics: a height-based lock must stay below the time threshold.
    if (settle_lock_height >= LOCKTIME_THRESHOLD) {
        err = "settle_lock_height must be a block height (< LOCKTIME_THRESHOLD)";
        return false;
    }
    // The CLTV must not be reachable before consensus considers the fixing buried. Compute the bound
    // in 64-bit to avoid uint32 wrap near the top of the range.
    const uint64_t min_lock = static_cast<uint64_t>(fixing_height) + static_cast<uint64_t>(DIFFCFD_MATURITY_DEPTH);
    if (static_cast<uint64_t>(settle_lock_height) < min_lock) {
        err = "settle_lock_height must be >= fixing_height + DIFFCFD_MATURITY_DEPTH";
        return false;
    }
    return true;
}

CScript BuildDifficultyLeafScript(const DifficultyContractRecord& record, bool is_short)
{
    const DifficultyContractTerms& terms = record.terms;
    const DifficultyLegTerms& leg = is_short ? terms.short_leg : terms.long_leg;
    CScript s;
    // Per-instance uniqueness commitment (inert: pushed then dropped). Makes the leaf — and therefore
    // the merkle root / NUMS_H-tweaked output key — unique per contract_id, so identical-terms
    // contracts with different salts get distinct vault addresses (no registry collision).
    s << ToByteVector(record.contract_id) << OP_DROP;
    // Belt-and-suspenders CLTV (consensus also enforces burial via the maturity bound).
    s << static_cast<int64_t>(terms.settle_lock_height) << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    // Strict fixed-width operands, exactly as OP_DIFFCFD_SETTLE decodes them (it reads each as a fixed
    // length 1-byte value off the stack, regardless of the push encoding).
    s << LE32(terms.fixing_height);
    s << LE32(terms.strike_nbits);
    s << LE32(leg.lambda_q);
    // Loss-direction operand (0x00 long / 0x01 short). Push it MINIMALLY so the leaf relays under standard
    // MINIMALDATA policy: a 1-byte data push of 0x01 is non-minimal (must be OP_1), while 0x00 is a clean
    // 1-byte push (NOT the empty vector OP_0 produces). OP_DIFFCFD_SETTLE reads the same {0x01}/{0x00}.
    if (is_short) {
        s << OP_1;                                       // {0x01} == DifficultyLossDirection(true)
    } else {
        s << std::vector<unsigned char>{DifficultyLossDirection(/*is_short=*/false)}; // {0x00}
    }
    s << LE64(static_cast<uint64_t>(leg.im));
    s << ToByteVector(leg.owner_key);
    s << ToByteVector(leg.cp_key);
    s << OP_DIFFCFD_SETTLE;
    return s;
}

CScript BuildDifficultyCoopLeafScript(const DifficultyContractRecord& record, bool is_short)
{
    CScript s;
    // Plain 2-of-2 cosign of the two parties' INTERNAL (descriptor) keys — the untweaked keys behind their
    // payout addresses. Each party signs with the internal private key from its payout address's expanded
    // signing provider:
    //   <owner_internal> OP_CHECKSIGVERIFY <cp_internal> OP_CHECKSIG
    s << ToByteVector(record.CoopOwnerInternal(is_short)) << OP_CHECKSIGVERIFY;
    s << ToByteVector(record.CoopCpInternal(is_short)) << OP_CHECKSIG;
    return s;
}

TaprootBuilder CreateDifficultyVaultBuilder(const DifficultyContractRecord& record, bool is_short,
                                            const XOnlyPubKey& internal_key)
{
    Assume(internal_key.IsFullyValid()); // an invalid internal key leaves the builder !IsComplete()
    // Two-leaf tree (both at depth 1): the unilateral settlement covenant + the cooperative 2-of-2 close.
    const CScript settle_leaf = BuildDifficultyLeafScript(record, is_short);
    const CScript coop_leaf = BuildDifficultyCoopLeafScript(record, is_short);
    TaprootBuilder builder;
    builder.Add(1, std::vector<unsigned char>(settle_leaf.begin(), settle_leaf.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    builder.Add(1, std::vector<unsigned char>(coop_leaf.begin(), coop_leaf.end()), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    builder.Finalize(internal_key);
    return builder;
}

uint256 ComputeDifficultyContractId(const DifficultyContractTerms& terms, const uint256& salt)
{
    HashWriter hw{};
    hw << terms << salt;
    return hw.GetHash();
}

double DifficultyNBitsToTokensPerSec(uint32_t nbits)
{
    arith_uint256 target;
    bool neg = false, of = false;
    target.SetCompact(nbits, &neg, &of);
    if (neg || of || target == 0) return 0.0;
    // 2^256/(target+1) — the expected number of 256-token genesis solution windows to find a block;
    // computed exactly as GetBlockProof() does (the chain's own per-block work metric).
    const arith_uint256 work = (~target / (target + 1)) + 1;
    constexpr double kSolutionWindowTokens = 256.0;  // genesis solution window W (Verification Whitepaper)
    constexpr double kBlockSpacingSec = 600.0;       // consensus.nPowTargetSpacing
    return work.getdouble() * kSolutionWindowTokens / kBlockSpacingSec;
}

uint32_t DifficultyTokensPerSecToNBits(double tokens_per_sec)
{
    if (!(tokens_per_sec > 0.0)) return 0;
    // Inverse of DifficultyNBitsToTokensPerSec so a human can strike in tok/s and the
    // UI derives the canonical compact target. tok/s = work * 256 / 600 with
    // work = 2^256/(target+1), hence work = tok/s * 600 / 256 and target ~= 2^256/work - 1.
    double work_d = tokens_per_sec * 600.0 / 256.0;
    if (work_d < 1.0) work_d = 1.0;
    // Build `work` as a 256-bit integer (work_d can exceed 2^64 at very high difficulty).
    arith_uint256 work;
    {
        double d = work_d;
        int shift = 0;
        while (d >= 18446744073709551616.0 /* 2^64 */ && shift < 192) {
            d /= 4294967296.0;  // 2^32
            shift += 32;
        }
        work = arith_uint256(static_cast<uint64_t>(d)) << shift;
    }
    if (work == 0) work = arith_uint256(1);
    // target ~= floor((2^256 - 1) / work) == 2^256/work - 1, to the precision the lossy
    // compact (nBits) encoding preserves anyway. Callers should display the REALIZED tok/s
    // (DifficultyNBitsToTokensPerSec of the result) since the round-trip is not bit-exact.
    arith_uint256 target = (~arith_uint256(0)) / work;
    if (target == 0) target = arith_uint256(1);
    return target.GetCompact();
}

std::string DifficultyFormatTokensPerSec(double tokens_per_sec)
{
    if (!(tokens_per_sec > 0.0)) return "n/a";
    static const char* const kSuffix[] = {"", "k", "M", "G", "T", "P"};
    int s = 0;
    double v = tokens_per_sec;
    while (v >= 1000.0 && s < 5) { v /= 1000.0; ++s; }
    const int prec = v < 10.0 ? 2 : (v < 100.0 ? 1 : 0);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.*f", prec, v);
    return std::string(buf) + kSuffix[s] + " tok/s";
}

uint256 ComputeDifficultyContractMeta(const DifficultyContractRecord& record)
{
    // Domain-separated; both parties compute identically once they hold the record. Binds the
    // contract id and both adaptor points so the open PSBT's fs/contract_meta resolves uniquely.
    HashWriter hw = TaggedHash("tensorcash/difficulty/fs-meta");
    hw << record.contract_id << record.fs_tx_adaptor_point;
    const bool has_cp = record.counterparty_adaptor_point.has_value();
    hw << has_cp;
    if (has_cp) hw << *record.counterparty_adaptor_point;
    return hw.GetSHA256();
}

uint256 ComputeDifficultyOfferCommitment(uint8_t proposer_is_short, const DifficultyContractTerms& terms,
                                         const XOnlyPubKey& proposer_owner_key,
                                         const XOnlyPubKey& proposer_cp_key, const uint256& salt)
{
    // Hash ONLY fields fixed at propose time: the econ scalars (NOT the leg payout keys, which carry the
    // acceptor's keys that are unset at propose), the proposer's own payout keys (passed explicitly),
    // its side, and the salt. Identical at propose / accept / import, so all parties share one context.
    HashWriter hw = TaggedHash("tensorcash/difficulty/fs-offer-commitment");
    hw << proposer_is_short
       << terms.strike_nbits << terms.fixing_height << terms.settle_lock_height
       << terms.kind << terms.premium
       << terms.long_leg.im << terms.long_leg.lambda_q
       << terms.short_leg.im << terms.short_leg.lambda_q
       << proposer_owner_key << proposer_cp_key << salt;
    return hw.GetSHA256();
}

uint256 ComputeDifficultyOptionOfferCommitment(uint8_t writer_is_short, uint8_t proposer_is_writer,
                                               uint32_t strike_nbits, uint32_t fixing_height,
                                               uint32_t settle_lock_height, CAmount im, uint32_t lambda_q,
                                               CAmount premium, const XOnlyPubKey& proposer_key,
                                               const uint256& salt)
{
    HashWriter hw = TaggedHash("tensorcash/difficulty/fs-offer-commitment-option");
    hw << writer_is_short << proposer_is_writer
       << strike_nbits << fixing_height << settle_lock_height
       << im << lambda_q << premium
       << proposer_key << salt;
    return hw.GetSHA256();
}

std::pair<uint256, XOnlyPubKey> DeriveDifficultyFsAdaptor(const CKey& owner_key, const uint256& salt,
                                                          const uint256& context, uint8_t role)
{
    if (!owner_key.IsValid()) {
        throw std::runtime_error("DeriveDifficultyFsAdaptor: owner key not available/invalid");
    }
    // scalar = H_tag(owner_priv || salt || context || role || counter). context + role bind the secret
    // to one contract and one side so a reused (owner key, salt) cannot repeat it; retry on the
    // ~2^-128 chance of an invalid scalar.
    for (uint8_t counter = 0; counter < 16; ++counter) {
        HashWriter hw = TaggedHash("tensorcash/difficulty/fs-adaptor");
        hw.write(MakeByteSpan(owner_key));
        hw << salt << context << role << counter;
        const uint256 scalar = hw.GetSHA256();
        CKey k;
        k.Set(scalar.begin(), scalar.end(), /*fCompressed=*/true);
        if (k.IsValid()) {
            const XOnlyPubKey xonly(k.GetPubKey());
            uint256 out;
            std::memcpy(out.data(), k.data(), 32);
            return {out, xonly};
        }
    }
    throw std::runtime_error("DeriveDifficultyFsAdaptor: no valid scalar derived");
}

bool BuildDifficultySettlementSkeleton(const DifficultyContractRecord& record, bool is_short,
                                       uint32_t realized_nbits, const uint256& pow_limit,
                                       DifficultySettlementSkeleton& out, std::string& err)
{
    const DifficultyContractTerms& terms = record.terms;

    // Same gate the consensus opcode applies (incl. the powLimit range on the strike).
    if (!terms.Validate(err, &pow_limit)) return false;

    const DifficultyLegTerms& leg = is_short ? terms.short_leg : terms.long_leg;

    // Compute the payout via the SAME path as consensus: DeriveTarget + ComputeDiffCfdPayout.
    const auto strike_target = DeriveTarget(terms.strike_nbits, pow_limit);
    const auto realized_target = DeriveTarget(realized_nbits, pow_limit);
    if (!strike_target || !realized_target) {
        err = "strike or realized nBits is out of range for the chain powLimit";
        return false;
    }
    DiffCfdPayout payout;
    if (!ComputeDiffCfdPayout(*strike_target, *realized_target, leg.lambda_q,
                              static_cast<uint64_t>(leg.im), /*short_leg=*/is_short, payout)) {
        err = "ComputeDiffCfdPayout rejected the leg terms";
        return false;
    }

    // Reconstruct the vault's control block from the stored internal key + the committed leaf, so the
    // witness always matches the on-chain output and the caller can't pass a mismatched control block.
    const CScript leaf = BuildDifficultyLeafScript(record, is_short);
    const std::vector<unsigned char> leafvec(leaf.begin(), leaf.end());
    TaprootBuilder builder = CreateDifficultyVaultBuilder(record, is_short, record.VaultInternalKey(is_short));
    if (!builder.IsComplete()) {
        err = "vault internal key is not set/valid (record not opened?)";
        return false;
    }
    const TaprootSpendData spend = builder.GetSpendData();
    const auto it = spend.scripts.find({leafvec, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT)});
    if (it == spend.scripts.end() || it->second.empty()) {
        err = "could not reconstruct the vault control block";
        return false;
    }
    const std::vector<unsigned char> control = *it->second.begin();

    // Build into a local and assign only on success, so `out` is never left in a stale/partial state.
    DifficultySettlementSkeleton result;

    // Vault input: keeper spend (witness = revealed leaf + control block, NO signature). Non-final
    // sequence so the leaf's CLTV is enforced; nLockTime == settle_lock_height.
    CTxIn vin(record.VaultOutpoint(is_short));
    vin.scriptWitness.stack = {leafvec, control};
    vin.nSequence = CTxIn::SEQUENCE_FINAL - 1; // 0xfffffffe: locktime-enabled, not RBF-final
    result.vault_input = std::move(vin);

    // Exact covenant outputs — a zero leg emits NO output, exactly as OP_DIFFCFD_SETTLE requires
    // (OP_OUTPUTMATCH_NATIVE rejects a 0-amount match). Outputs are never shaved for fees.
    if (payout.payout_owner > 0) result.payouts.emplace_back(static_cast<CAmount>(payout.payout_owner), P2TR(leg.owner_key));
    if (payout.payout_cp > 0)    result.payouts.emplace_back(static_cast<CAmount>(payout.payout_cp),    P2TR(leg.cp_key));

    result.nlocktime = terms.settle_lock_height;
    result.payout = payout;

    out = std::move(result);
    return true;
}

} // namespace wallet
