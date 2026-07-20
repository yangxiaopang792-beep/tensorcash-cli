// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <consensus/zk_utils.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <span.h>
#include <assets/asset.h>
#include <assets/icu_acceptance_record.h>
#include <assets/canonical_vk.h>
#include <assets/kyc_delegation.h>
#include <assets/sighash_utils.h>
#include <crypto/groth16.h>
#include <script/solver.h>
#include <assets/registry.h>
#include <chainparams.h>
#include <logging.h>
#include <optional>
#include <set>

namespace Consensus {

bool IsWitnessScriptType(const CScript& scriptPubKey)
{
    std::vector<std::vector<unsigned char>> vSolutions;
    TxoutType which = Solver(scriptPubKey, vSolutions);
    return (which == TxoutType::WITNESS_V0_KEYHASH ||
            which == TxoutType::WITNESS_V0_SCRIPTHASH ||
            which == TxoutType::WITNESS_V1_TAPROOT);
}

bool HasValidZkWitnessLayout(const CScriptWitness& witness)
{
    // Witness layout validation for TLV-based proof transport.
    //
    // With ZK_PROOF_PAYLOAD TLV (type 0x22), witness contains only standard
    // spend elements (signature + pubkey), not the ZK proof itself.
    // Proof presence is validated separately via zk_proof_payloads map.
    //
    // This check ensures witness is non-empty (signature present for segwit).

    if (witness.stack.empty()) {
        return false;
    }
    return true;
}

bool IsProofCountWithinLimit(size_t proof_count)
{
    return proof_count <= assets::MAX_ZK_PROOFS_PER_TX;
}

} // namespace Consensus

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;

    // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
    // transaction is still considered final if all inputs' nSequence ==
    // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
    //
    // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
    // also check that the spending input's nSequence != SEQUENCE_FINAL,
    // ensuring that an unsatisfied nLockTime value will actually cause
    // IsFinalTx() to return false here:
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, uint32_t flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee, bool skip_expensive_zk_verification)
{
    LogDebug(BCLog::VALIDATION, "CheckTxInputs: START tx=%s\n", tx.GetHash().ToString());
    // Assets activation gating: before activation height, any vExt usage is consensus-invalid
    if (nSpendHeight < ::Params().GetConsensus().AssetsHeight) {
        for (const auto& out : tx.vout) {
            if (!out.vExt.empty()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "outext");
            }
        }
    }
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;

    // Phase 3: Asset Δ validation (conservation + ICU authorization) + registry/policy enforcement
    // Build per-asset delta from inputs (negative) and outputs (positive)
    // and detect ICU spends (IssuerReg inputs).
    std::map<uint256, __int128_t> delta;
    auto add_safe = []( __int128_t cur, uint64_t add, bool& of ) -> __int128_t {
        const __int128_t mx = std::numeric_limits<__int128_t>::max();
        if (cur > 0 && (__int128_t)add > (mx - cur)) { of = true; return cur; }
        return cur + (__int128_t)add;
    };
    auto sub_safe = []( __int128_t cur, uint64_t sub, bool& of ) -> __int128_t {
        const __int128_t mn = std::numeric_limits<__int128_t>::min();
        if (cur < 0 && -(__int128_t)sub < (mn - cur)) { of = true; return cur; }
        return cur - (__int128_t)sub;
    };
    bool arith_overflow = false;
    std::set<uint256> icu_spent;
    // Capture IssuerReg entries seen in inputs (the currently-authorizing ICU),
    // so we can enforce policy_bits and allowed_spk_families when minting/burning.
    std::map<uint256, assets::IssuerReg> input_regs;
    std::map<uint256, std::vector<int>> asset_input_indices;
    std::map<uint256, std::vector<int>> issuer_input_indices;
    std::map<uint256, std::vector<assets::TfrAnchor>> tfr_anchors;
    std::map<uint256, std::vector<assets::ZkProofPayload>> zk_proof_payloads;  // TLV-based proof collection
    size_t zk_proof_count{0};

    // Inputs: accumulate spends and ICU presence
    for (unsigned int input_index = 0; input_index < tx.vin.size(); ++input_index) {
        const CTxIn& txin = tx.vin[input_index];
        const Coin& coin = inputs.AccessCoin(txin.prevout);
        const CTxOut& prev = coin.out;
        if (!prev.vExt.empty()) {
            if (auto tag = assets::ParseAssetTag(prev.vExt)) {
                delta[tag->id] = sub_safe(delta[tag->id], tag->amount, arith_overflow);
                asset_input_indices[tag->id].push_back(static_cast<int>(input_index));
            }
            if (auto reg = assets::ParseIssuerReg(prev.vExt)) {
                icu_spent.insert(reg->asset_id);
                input_regs.emplace(reg->asset_id, *reg);
                issuer_input_indices[reg->asset_id].push_back(static_cast<int>(input_index));
            }
        }
    }

    // Enforce SIGHASH_ALL (or Taproot SIGHASH_DEFAULT) for every ICU-spending input.
    //
    // Security rationale (Pattern #15): ICU signatures authorise mint/burn operations. Using
    // ANYONECANPAY/SINGLE/NONE allows attackers to graft additional inputs/outputs after the
    // issuer signs, violating asset conservation and policy controls. We therefore require at
    // least one signature per ICU input and mandate output-binding sighashes.
    std::set<int> checked_icu_inputs;
    for (const auto& [asset_id, indices] : issuer_input_indices) {
        (void)asset_id;
        for (int input_index : indices) {
            if (!checked_icu_inputs.insert(input_index).second) {
                continue;
            }
            const assets::SighashScanResult scan = assets::ScanInputSighashes(
                tx.vin[input_index], assets::IsOutputBindingSighash);
            if (!scan.saw_signature) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "icu-missing-signature");
            }
            if (!scan.ok) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "icu-invalid-sighash");
            }
        }
    }

    // Outputs: validate TLV type, accumulate creates and collect script families per asset
    std::map<uint256, uint16_t> output_families_mask; // union of families seen for an asset in this tx
    for (const auto& out : tx.vout) {
        if (!out.vExt.empty()) {
            // Consensus: only known TLV types are permitted
            auto tag = assets::ParseAssetTag(out.vExt);
            const bool is_asset = static_cast<bool>(tag);
            const bool is_issuer = static_cast<bool>(assets::ParseIssuerReg(out.vExt));
            const bool is_chunk = static_cast<bool>(assets::ParseZkParamsChunk(out.vExt));
            const bool is_icu_chunk = static_cast<bool>(assets::ParseIcuTextChunk(out.vExt));
            const bool is_anchor = static_cast<bool>(assets::ParseTfrAnchor(out.vExt));
            const bool is_zk_proof = static_cast<bool>(assets::ParseZkProofPayload(out.vExt));
            const bool is_keywrap = static_cast<bool>(assets::ParseIcuKeywrap(out.vExt));
            const bool is_accept = static_cast<bool>(assets::ParseIcuAcceptanceTLV(out.vExt));  // 0x40 ICU acceptance record (fail-closed parse)
            // ISSUER_SCALAR (0x11) is a known type only at/above ScalarCfdHeight, mirroring
            // the AssetsHeight gate above and the ConnectBlock allowlist (CFD_GENERALISATION.md §3.3).
            const bool is_scalar = (nSpendHeight >= ::Params().GetConsensus().ScalarCfdHeight)
                                   && static_cast<bool>(assets::ParseIssuerScalar(out.vExt));
            if (!is_asset && !is_issuer && !is_chunk && !is_icu_chunk && !is_anchor && !is_zk_proof && !is_keywrap && !is_accept && !is_scalar) {
                LogPrintf("TX_VERIFY_DEBUG: Unknown vExt type. vExt_size=%zu type=0x%02x is_asset=%d is_issuer=%d is_chunk=%d is_icu_chunk=%d is_anchor=%d is_zk_proof=%d is_keywrap=%d\n",
                          out.vExt.size(), out.vExt.empty() ? 0 : out.vExt[0], is_asset, is_issuer, is_chunk, is_icu_chunk, is_anchor, is_zk_proof, is_keywrap);
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "outext");
            }
            if (is_asset) {
                // sanity: zero amount is invalid
                if (tag->amount == 0) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-amount-zero");
                }
                // Reserved bits for AssetTag.flags must be zero (consensus)
                if (tag->flags != 0) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-unknown-flag");
                }
                delta[tag->id] = add_safe(delta[tag->id], tag->amount, arith_overflow);
                // classify scriptPubKey family
                std::vector<std::vector<unsigned char>> vSolutions;
                TxoutType which = Solver(out.scriptPubKey, vSolutions);
                uint16_t fam = 0;
                switch (which) {
                    case TxoutType::PUBKEYHASH: fam = assets::SPK_P2PKH; break;
                    case TxoutType::SCRIPTHASH: fam = assets::SPK_P2SH; break;
                    case TxoutType::WITNESS_V0_KEYHASH: fam = assets::SPK_P2WPKH; break;
                    case TxoutType::WITNESS_V0_SCRIPTHASH: fam = assets::SPK_P2WSH; break;
                    case TxoutType::WITNESS_V1_TAPROOT: fam = assets::SPK_P2TR; break;
                    case TxoutType::WITNESS_V2_TAPROOT: fam = assets::SPK_P2TR_V2; break; // PQ (ML-DSA)
                    default: fam = 0; break;
                }
                // Close the witness-version gap: reject AssetTag value outputs on an
                // UNSUPPORTED witness version (v3+/unknown). Like the old witness-v2 case,
                // those classify as fam=0 and would silently pass the mask check
                // ((0 & mask)!=0 is false), letting a value output bypass allowed_spk_families.
                // Witness-v2 (PQ) is now handled above via SPK_P2TR_V2. Non-witness nonstandard
                // scripts keep their prior fam=0 (mask-permissive) handling — tightening THOSE
                // is a separate, broader behavioral change, not part of the PQ fix.
                // (Consensus tightening — gate behind an activation height if such outputs
                // already exist on a live chain.)
                if (which == TxoutType::WITNESS_UNKNOWN) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-spk-unknown-family");
                }
                output_families_mask[tag->id] |= fam;
            }
            if (is_issuer) {
                // Narrow, PQ-SPECIFIC guard (NOT a general "ICU must be spendable" rule):
                // reject only witness-v2 (ML-DSA) and unknown-version ICU outputs. Those would
                // later fail the ICU sighash check with "icu-missing-signature" — the scanner
                // can't parse ML-DSA sigs — permanently bricking mint/burn/rotation. A general
                // spendable-only allowlist is intentionally NOT enforced here because legitimate
                // ICU retirement to a provably-unspendable NULL_DATA/burn output must stay valid.
                // Lift this once ICU sighash scanning supports ML-DSA.
                std::vector<std::vector<unsigned char>> icuSolutions;
                TxoutType iwhich = Solver(out.scriptPubKey, icuSolutions);
                if (iwhich == TxoutType::WITNESS_V2_TAPROOT || iwhich == TxoutType::WITNESS_UNKNOWN) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "icu-spk-unsupported");
                }
            }
            if (is_chunk) {
                auto parsed = assets::ParseZkParamsChunk(out.vExt);
                if (!assets::ValidateChunkParams(*parsed)) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "zkchunk-invalid");
                }
            }
            if (is_anchor) {
                auto parsed = assets::ParseTfrAnchor(out.vExt);
                if (parsed->locator.size() > assets::MAX_TFR_LOCATOR_SIZE) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "tfr-anchor-size");
                }
                tfr_anchors[parsed->asset_id].push_back(*parsed);
            }
            if (is_zk_proof) {
                auto parsed = assets::ParseZkProofPayload(out.vExt);
                if (!parsed) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-parse-failed");
                }
                // Validate Groth16 proof size (192 bytes: compressed A||B||C)
                if (parsed->proof.size() != assets::GROTH16_PROOF_SIZE) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-size");
                }
                // Validate public inputs size: must be a multiple of 32 bytes,
                // at least 4 elements (128 bytes), and within the max DoS limit.
                // The VK encodes the exact expected count; consensus verifies the match later.
                if (parsed->public_inputs.size() < assets::GROTH16_MIN_PUBLIC_INPUTS * assets::GROTH16_FR_SIZE ||
                    parsed->public_inputs.size() > assets::GROTH16_MAX_PUBLIC_INPUTS_SIZE ||
                    (parsed->public_inputs.size() % assets::GROTH16_FR_SIZE) != 0) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-public-inputs-size");
                }
                // Store proof payload (one per asset; duplicates rejected later)
                zk_proof_payloads[parsed->asset_id].push_back(*parsed);
            }
        }
    }
    // Coinbase may not change asset supply
    if (arith_overflow) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-arith-overflow");
    }
    if (tx.IsCoinBase()) {
        for (const auto& [aid, d] : delta) {
            if (d != 0) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-coinbase-forbidden");
            }
        }
    }
    // Prepare local registrations in this tx (if any)
    std::map<uint256, assets::IssuerReg> local_regs;
    for (const auto& out : tx.vout) {
        if (auto reg = assets::ParseIssuerReg(out.vExt)) {
            auto [it, inserted] = local_regs.emplace(reg->asset_id, *reg);
            if (!inserted) {
                it->second = *reg;
            }
            if (auto in_it = input_regs.find(reg->asset_id); in_it != input_regs.end()) {
                const bool prev_burn_allowed = (in_it->second.policy_bits & assets::BURN_ALLOWED) != 0;
                const bool new_burn_allowed = (reg->policy_bits & assets::BURN_ALLOWED) != 0;
                if (!prev_burn_allowed && new_burn_allowed) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-policy-burn-flip");
                }
            }
        }
    }

    struct KycPolicySnapshot {
        bool required{false};
        uint256 vk_commitment{};
        uint32_t max_root_age{0};
        uint32_t tfr_flags{0};
        uint256 compliance_root_commit{};  // Active commitment (zero = not set)
        std::deque<ComplianceRootHistory> compliance_root_history;  // Ring buffer for historical roots
        // Effective-policy resolution (delegation). For a delegating asset B these
        // are sourced from A; tfr_flags + the expected asset id stay B's.
        std::deque<uint256> compliance_root_history_vk;  // per-historical-root VK (rolling migration)
        bool delegated{false};
        int32_t active_root_activation_height{0};        // heartbeat (delegated assets)
    };
    std::map<uint256, KycPolicySnapshot> kyc_policies;

    // Asset-registry state is read through the coins view stack via the virtual
    // CCoinsView asset accessors (ReadAssetPolicy / ReadZkVerifyingKey / ...),
    // which forward down to the backing CCoinsViewDB. (Previously this walked the
    // CCoinsViewBacked chain with dynamic_cast to obtain the CCoinsViewDB directly.)

    // Enforce conservation (Δ==0) and ICU‑authorization for mint/burn (Δ!=0), policy bits, and allowed script families
    for (const auto& [aid, d] : delta) {
        const bool issuer_auth = (icu_spent.count(aid) != 0);

        // Determine policy_bits and allowed_spk_families from local reg or DB (if available)
        uint32_t policy_bits = 0xFFFFFFFFu; // default allow for mint/burn unless overridden
        uint16_t allowed_mask = assets::SPK_DEFAULT_ALLOWED;
        std::optional<assets::IssuerReg> reg_source;
        if (auto it = local_regs.find(aid); it != local_regs.end()) {
            policy_bits = it->second.policy_bits;
            allowed_mask = it->second.allowed_spk_families ? it->second.allowed_spk_families : ((policy_bits & assets::BURN_JOINT_REQUIRED) ? assets::SPK_HOLDER_ONLY : assets::SPK_DEFAULT_ALLOWED);
            reg_source = it->second;
        } else if (auto in_it = input_regs.find(aid); in_it != input_regs.end()) {
            // If an ICU for this asset is being spent, treat its policy as authoritative
            policy_bits = in_it->second.policy_bits;
            allowed_mask = in_it->second.allowed_spk_families ? in_it->second.allowed_spk_families : ((policy_bits & assets::BURN_JOINT_REQUIRED) ? assets::SPK_HOLDER_ONLY : assets::SPK_DEFAULT_ALLOWED);
            reg_source = in_it->second;
        } else {
            AssetRegistryEntry e;
            if (inputs.ReadAssetPolicy(aid, e)) {
                LogDebug(BCLog::VALIDATION, "CheckTxInputs: ReadAssetPolicy SUCCESS for asset %s, has_kyc=%d\n", aid.ToString(), e.has_kyc);
                policy_bits = e.policy_bits;
                allowed_mask = e.allowed_spk_families ? e.allowed_spk_families : ((policy_bits & assets::BURN_JOINT_REQUIRED) ? assets::SPK_HOLDER_ONLY : assets::SPK_DEFAULT_ALLOWED);
                if (e.has_kyc) {
                    // Resolve the EFFECTIVE policy: a delegating asset B follows source A's
                    // VK/root/history while keeping its own asset id + tfr. The source is
                    // read from the committed registry state in the current view. Intra-block
                    // updates to A (e.g. a same-block rotation) are NOT guaranteed visible
                    // here — registry mutations are staged and applied later in block
                    // connection — so do not rely on observing them during input validation.
                    const AssetRegistryEntry* src = nullptr;
                    AssetRegistryEntry src_entry;
                    if (!e.compliance_delegate_asset_id.IsNull() && e.compliance_delegate_asset_id != aid &&
                        inputs.ReadAssetPolicy(e.compliance_delegate_asset_id, src_entry)) {
                        src = &src_entry;
                    }
                    const assets::EffectiveKycPolicy eff =
                        assets::ResolveEffectiveKycPolicy(aid, e, src, assets::IsCanonicalVk);
                    if (!eff.ok) {
                        return state.Invalid(TxValidationResult::TX_CONSENSUS, eff.reason);
                    }
                    KycPolicySnapshot snap;
                    snap.required = true;
                    snap.vk_commitment = eff.vk_commitment;
                    snap.max_root_age = eff.max_root_age;
                    snap.tfr_flags = eff.tfr_flags;
                    snap.compliance_root_commit = eff.compliance_root_commit;
                    snap.compliance_root_history = eff.compliance_root_history;
                    snap.compliance_root_history_vk = eff.compliance_root_history_vk;
                    snap.delegated = eff.delegated;
                    snap.active_root_activation_height = eff.active_root_activation_height;
                    kyc_policies[aid] = snap;
                    LogDebug(BCLog::VALIDATION, "CheckTxInputs: KYC policy loaded for asset %s (delegated=%d)\n", aid.ToString(), eff.delegated);
                }
            } else {
                LogPrintf("CheckTxInputs: ReadAssetPolicy FAILED for asset %s - policy not found in DB\n", aid.ToString());
            }
        }
        if (reg_source && (reg_source->kyc_flags != 0) && (reg_source->kyc_flags & assets::KYC_REQUIRED)) {
            // In-flight registration/rotation in this same tx. Build a partial entry from
            // the reg and resolve. A non-delegating reg has empty history (holders wait
            // one block); a DELEGATING reg follows the source's already-confirmed root, so
            // it can spend immediately.
            AssetRegistryEntry b_entry;
            b_entry.has_kyc = true;
            b_entry.zk_vk_commitment = reg_source->zk_vk_commitment;
            b_entry.max_root_age = reg_source->max_root_age;
            b_entry.tfr_flags = reg_source->tfr_flags;
            b_entry.compliance_root_commit = reg_source->compliance_root_commit;
            // Normalize the in-flight reg's delegate EXACTLY like the registry-update path:
            // a same-tx v1 rotation inherits the prior delegate, a v2-self reg clears it.
            // Building straight from reg_source would lose a preserved delegate (v1) or
            // mis-read an opt-out as self-delegation (v2-self).
            {
                AssetRegistryEntry prev_e;
                const uint256 prev_deleg = inputs.ReadAssetPolicy(aid, prev_e)
                    ? prev_e.compliance_delegate_asset_id : uint256{};
                b_entry.compliance_delegate_asset_id =
                    assets::ResolveRegDelegate(*reg_source, aid, prev_deleg);
            }
            const AssetRegistryEntry* src = nullptr;
            AssetRegistryEntry src_entry;
            if (!b_entry.compliance_delegate_asset_id.IsNull() && b_entry.compliance_delegate_asset_id != aid &&
                inputs.ReadAssetPolicy(b_entry.compliance_delegate_asset_id, src_entry)) {
                src = &src_entry;
            }
            const assets::EffectiveKycPolicy eff =
                assets::ResolveEffectiveKycPolicy(aid, b_entry, src, assets::IsCanonicalVk);
            if (!eff.ok) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, eff.reason);
            }
            KycPolicySnapshot snap;
            snap.required = true;
            snap.vk_commitment = eff.vk_commitment;
            snap.max_root_age = eff.max_root_age;
            snap.tfr_flags = eff.tfr_flags;
            snap.compliance_root_commit = eff.compliance_root_commit;
            snap.compliance_root_history = eff.compliance_root_history;
            snap.compliance_root_history_vk = eff.compliance_root_history_vk;
            snap.delegated = eff.delegated;
            snap.active_root_activation_height = eff.active_root_activation_height;
            kyc_policies[aid] = snap;
        }
        if (policy_bits != 0xFFFFFFFFu && (policy_bits & assets::BURN_JOINT_REQUIRED)) {
            // Clamp to holder-only families if joint-required
            allowed_mask &= assets::SPK_HOLDER_ONLY;
        }

        if (d == 0) {
            continue;
        }

        if (d > 0) { // mint
            // Require ICU and MINT_ALLOWED when known
            if (!issuer_auth) return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-mint-unauthorized");
            // If policy bits known, enforce mint allowed
            if (policy_bits != 0xFFFFFFFFu && !(policy_bits & assets::MINT_ALLOWED)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-mint-disallowed");
            }
        } else { // burn
            // Always require ICU for burn per plan
            if (!issuer_auth) return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-burn-needs-icu");
            if (policy_bits != 0xFFFFFFFFu && !(policy_bits & assets::BURN_ALLOWED)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-burn-disallowed");
            }
        }
        // Enforce allowed script families for any AssetTag outputs of this asset
        if (auto fam_it = output_families_mask.find(aid); fam_it != output_families_mask.end()) {
            uint16_t fams = fam_it->second;
            if ((fams & allowed_mask) != fams) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-spk-not-allowed");
            }
        }
    }

    // KYC Witness Validation Pass: Enforce segwit families and witness presence
    //
    // Design: KYC assets use a one-proof-per-asset-per-transaction model.
    // - A single ZK proof attests to the holder's compliance status for an asset.
    // - When spending multiple UTXOs of the same KYC asset in one tx, all inputs
    //   must carry witness data (for standard script validation), but only the
    //   first input's proof will be cryptographically verified.
    // - This reduces computational cost while maintaining security: the proof
    //   implicitly covers the holder's authority to spend all inputs of that asset.
    //
    // This loop validates:
    // 1. All KYC asset inputs use segwit script families (P2WPKH/P2WSH/P2TR)
    // 2. All KYC asset inputs have witness data with proof+public_inputs layout
    // 3. Count one proof per asset for DoS cap enforcement
    LogDebug(BCLog::VALIDATION, "CheckTxInputs: entering KYC validation loop, kyc_policies.size=%d\n", kyc_policies.size());
    for (const auto& [aid, policy] : kyc_policies) {
        LogDebug(BCLog::VALIDATION, "CheckTxInputs: checking KYC policy for asset %s\n", aid.ToString());
        if (!policy.required) continue;
        if (policy.vk_commitment.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zkchunk-missing");
        }

        // TFR Anchor Per-Output Policy: Count outputs and anchors must match
        if ((policy.tfr_flags & assets::TFR_ANCHOR_REQUIRED)) {
            // Count AssetTag outputs for this asset
            size_t asset_output_count = 0;
            for (const auto& out : tx.vout) {
                if (auto tag = assets::ParseAssetTag(out.vExt)) {
                    if (tag->id == aid) ++asset_output_count;
                }
            }

            // Count TFR_ANCHOR TLVs for this asset
            size_t anchor_count = tfr_anchors[aid].size();

            // Require anchor count to match output count (per-output policy)
            if (anchor_count == 0) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "tfr-anchor-missing");
            }
            if (anchor_count != asset_output_count) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "tfr-anchor-count-mismatch");
            }
        }

        auto it_inputs = asset_input_indices.find(aid);
        if (it_inputs == asset_input_indices.end() || it_inputs->second.empty()) {
            continue; // no asset inputs touched by this tx (e.g. initial mint/registration)
        }

        // Enforce output-binding sighashes for all KYC asset inputs (Pattern #15 extension).
        //
        // Security rationale: KYC asset spends include compliance proofs that bind to transaction
        // outputs. Using ANYONECANPAY/SINGLE/NONE allows third parties (miners, coordinators) to
        // rebind the proof to different outputs after the holder signs, violating compliance controls.
        // This extends the same protection already applied to ICU inputs (tx_verify.cpp:303-321).
        //
        // Exception: Rotation transactions are exempt because ballot inputs require ANYONECANPAY
        // for parallel signing. The ICU input in rotation txs is already covered by the stricter
        // ICU check, and ballot inputs use the self-bounce pattern with zero asset delta.
        //
        // KYC HARDENING (F2): the exemption must apply ONLY to a structurally genuine
        // rotation, never to any tx that merely sets the ROTATION_TX_FLAG version bit.
        // IsRotationTx() is just that author-controlled bit; the compensating rotation
        // structural validation (proposal-hash binding + quorum, ConnectBlock) is gated
        // on `tx.vin.size() > 1`. A 1-input KYC transfer could therefore self-flag as a
        // rotation to (a) skip this output-binding sighash rule — admitting SIGHASH_NONE/
        // SINGLE/ANYONECANPAY signatures that do not commit to the outputs — and (b) skip
        // the rotation checks (vin == 1), reopening output/proof rebinding.
        //
        // The waiver is PER-INPUT, granted only to inputs that are genuine rotation ballots.
        // Everything else (the ICU input, non-ballot inputs of the rotated asset, inputs of
        // unrelated assets, every input of a non-rotation tx) must satisfy the strict
        // output-binding sighash rule. This closes two gaps the earlier per-tx/per-asset
        // waiver left open: (1) a rotation of asset A smuggling a weak-sighash spend of asset
        // B, and (2) a rotation of asset A carrying a non-ballot asset-A input with a weak
        // sighash.
        //
        // An input qualifies as a ballot ONLY if the tx has the rotation shape (flag,
        // vin > 1, vout[0] is an IssuerReg for THIS asset) AND the input itself is a validated
        // self-bounce: it spends asset `aid`, the paired output at the same index re-emits the
        // same asset and amount, and that output carries proposal_hash == the tx's proposal
        // hash. Even then it does not get a blanket pass — it must use a ballot sighash
        // (strict, or SIGHASH_SINGLE|ANYONECANPAY which commits the input to its own output).
        // SIGHASH_NONE and other weak forms are still rejected (IsBallotSighash).
        bool rotation_of_this_asset = false;
        if (IsRotationTx(tx) && tx.vin.size() > 1 && !tx.vout.empty()) {
            if (auto rot_reg = assets::ParseIssuerReg(tx.vout[0].vExt)) {
                rotation_of_this_asset = (rot_reg->asset_id == aid);
            }
        }
        const uint256 proposal_hash = rotation_of_this_asset
            ? ComputeRotationProposalHash(tx)
            : uint256();

        for (int input_index : it_inputs->second) {
            bool is_ballot = false;
            if (rotation_of_this_asset
                && input_index > 0
                && static_cast<size_t>(input_index) < tx.vout.size()) {
                const Coin& coin = inputs.AccessCoin(tx.vin[input_index].prevout);
                const auto in_tag = assets::ParseAssetTag(coin.out.vExt);
                const auto out_tag = assets::ParseAssetTag(tx.vout[input_index].vExt);
                if (in_tag && out_tag
                    && in_tag->id == aid && out_tag->id == aid
                    && in_tag->amount == out_tag->amount          // zero asset delta (self-bounce)
                    && out_tag->has_proposal_hash
                    && out_tag->proposal_hash == proposal_hash) {
                    is_ballot = true;
                }
            }

            const auto scan = assets::ScanInputSighashes(
                tx.vin[input_index],
                is_ballot ? assets::IsBallotSighash : assets::IsOutputBindingSighash
            );
            if (scan.saw_signature && !scan.ok) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-invalid-sighash");
            }
        }

        // Validate witness layout for all inputs, count one proof per asset
        bool counted_asset{false};
        bool skip_kyc_validation = false;  // Flag to skip validation if in mempool check context
        LogDebug(BCLog::VALIDATION, "CheckTxInputs: validating witness layout for %d inputs\n", it_inputs->second.size());
        for (int input_index : it_inputs->second) {
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: accessing coin for input %d\n", input_index);
            const Coin& coin = inputs.AccessCoin(tx.vin[input_index].prevout);
            if (coin.IsSpent()) {
                LogPrintf("CheckTxInputs: WARNING - coin is spent! Skipping all KYC validation for this asset (mempool consistency check context)\n");
                skip_kyc_validation = true;
                break;  // Skip entire KYC validation for this asset
            }

            // Check script type is witness-compatible
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: checking witness script type for input %d\n", input_index);
            if (!IsWitnessScriptType(coin.out.scriptPubKey)) {
                LogPrintf("CheckTxInputs: FAIL - input %d is not witness script type\n", input_index);
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-spend-nonsegwit");
            }

            // Witness layout validation (signature presence check only)
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: checking witness layout for input %d\n", input_index);
            const auto& witness = tx.vin[input_index].scriptWitness;
            if (!HasValidZkWitnessLayout(witness)) {
                LogPrintf("CheckTxInputs: FAIL - input %d has invalid witness layout, witness.stack.size=%d\n",
                         input_index, witness.stack.size());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-witness-empty");
            }
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: input %d passed witness checks\n", input_index);

            // Count one proof per asset (not per input) for DoS cap
            if (!counted_asset) {
                ++zk_proof_count;
                counted_asset = true;
            }
        }

        // Skip ZK proof validation if we're in mempool consistency check context
        LogDebug(BCLog::VALIDATION, "CheckTxInputs: finished witness loop, skip_kyc_validation=%d\n", skip_kyc_validation);
        if (skip_kyc_validation) {
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: skipping ZK_PROOF_PAYLOAD validation for asset %s (mempool check)\n", aid.ToString());
            continue;
        }

        // Validate ZK_PROOF_PAYLOAD TLV presence (exactly one per asset required)
        LogDebug(BCLog::VALIDATION, "CheckTxInputs: checking ZK_PROOF_PAYLOAD presence for asset %s, zk_proof_payloads.size=%d\n",
                 aid.ToString(), zk_proof_payloads.size());
        auto proof_it = zk_proof_payloads.find(aid);
        LogDebug(BCLog::VALIDATION, "CheckTxInputs: find() returned, checking if found\n");
        if (proof_it == zk_proof_payloads.end() || proof_it->second.empty()) {
            LogPrintf("CheckTxInputs: FAIL - ZK proof missing or empty for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-missing");
        }
        if (proof_it->second.size() > 1) {
            LogPrintf("CheckTxInputs: FAIL - duplicate ZK proofs for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-duplicate");
        }
        LogDebug(BCLog::VALIDATION, "CheckTxInputs: ZK_PROOF_PAYLOAD validation passed for asset %s\n", aid.ToString());
    }

    // Groth16 Proof Verification Pass: Cryptographically verify compliance proofs
    //
    // Proofs are transported via ZK_PROOF_PAYLOAD TLV (type 0x22) in transaction outputs.
    //
    // For each KYC asset with inputs in this transaction:
    // 1. Retrieve the verifying key from the VK cache (indexed by vk_commitment)
    // 2. Extract proof + public_inputs from ZK_PROOF_PAYLOAD TLV (one per asset)
    // 3. Construct verification context with policy parameters and on-chain anchors
    // 4. Invoke Groth16 pairing check with policy-layer binding validation
    //
    // Public Input Schema (see crypto/groth16.cpp for full specification):
    //
    // Legacy (4 inputs, 128 bytes):
    //   [0] = chain/domain separator (prevents cross-chain replay)
    //   [1] = asset_id commitment (binds proof to this asset)
    //   [2] = compliance root || height (Merkle root + freshness, packed)
    //   [3] = tfr_commit (transfer reporting anchor, or zero if not required)
    //
    // HDv1 (6 inputs, 192 bytes):
    //   [0] = chain/domain separator
    //   [1] = asset_id commitment
    //   [2] = compliance root (pure 32-byte MiMC root; freshness via on-chain history)
    //   [3] = tfr_commit
    //   [4] = output_key_high (upper 128 bits of child x-only key, left-padded to 32 bytes)
    //   [5] = output_key_low  (lower 128 bits of child x-only key, left-padded to 32 bytes)
    const std::array<unsigned char, 32> chain_separator_bytes = Consensus::ComputeChainSeparatorBytes(::Params());
    LogDebug(BCLog::VALIDATION, "CheckTxInputs: chain_separator for this network = %s\n", HexStr(chain_separator_bytes));

    for (const auto& [aid, policy] : kyc_policies) {
        if (!policy.required) continue;

        // Skip ZK verification only for explicit mempool consistency checks.
        if (skip_expensive_zk_verification) {
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: skipping ZK verification for asset %s (mempool consistency check, already verified on acceptance)\n", aid.ToString());
            continue;
        }

        // NOTE: the verifying key is fetched AFTER the root match below, so a
        // historical-root spend can be verified under THAT root's own VK (rolling
        // circuit migration). The active-root case still uses policy.vk_commitment.
        // A view with no asset-backing store will fail zk-vk-missing at that point.

        auto inputs_it = asset_input_indices.find(aid);
        if (inputs_it == asset_input_indices.end() || inputs_it->second.empty()) {
            continue;
        }

        // Extract proof + public inputs from ZK_PROOF_PAYLOAD TLV
        // (one-proof-per-asset model: one TLV per asset in transaction outputs)
        auto proof_it = zk_proof_payloads.find(aid);
        if (proof_it == zk_proof_payloads.end() || proof_it->second.empty()) {
            LogPrintf("CheckTxInputs: proof missing for asset %s (map size=%zu)\n", aid.ToString(), zk_proof_payloads.size());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-missing");
        }
        const assets::ZkProofPayload& zk_payload = proof_it->second.front();

        // Validate asset_id binding (prevent proof reuse across different assets)
        if (zk_payload.asset_id != aid) {
            LogPrintf("CheckTxInputs: proof asset mismatch proof=%s expected=%s\n", zk_payload.asset_id.ToString(), aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-asset-mismatch");
        }

        std::span<const unsigned char> proof_span(zk_payload.proof.data(), zk_payload.proof.size());
        std::span<const unsigned char> pub_span(zk_payload.public_inputs.data(), zk_payload.public_inputs.size());

        constexpr size_t REQUIRED_PUBLIC_INPUTS = 4 * groth16::GROTH16_FR_SIZE;
        if (pub_span.size() < REQUIRED_PUBLIC_INPUTS) {
            LogPrintf("CheckTxInputs: public inputs too short for asset %s (got %zu)\n", aid.ToString(), pub_span.size());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-public-inputs-short");
        }

        // KYC HARDENING (F1): require the output-bound public-input INTERFACE.
        //
        // Consensus pins a fixed public-input prefix, not the circuit. It never inspects the
        // circuit: the proof is checked against the issuer's registered VK (which the issuer
        // can rotate freely), and consensus reads:
        //
        //   [0]=chain  [1]=asset  [2]=root  [3]=anchor  [4]=key_high  [5]=key_low
        //
        // and byte-compares [4],[5] to the prevout x-only key. A 4-input ("standard") proof
        // has no [4],[5] at all, so it cannot be bound — bearer-token forgery (the legacy
        // bug). Requiring >= 6 fields makes that impossible.
        //
        // IMPORTANT — what this does NOT prove (issuer-VK trust assumption):
        //   The byte-compare guarantees the VALUES at [4],[5] equal the prevout key. It does
        //   NOT prove the circuit actually CONSTRAINS [4],[5] to the enrolled-pubkey
        //   derivation. A buggy/malicious VK could expose [4],[5] as free public inputs; the
        //   prover would then set them to the prevout key and pass both the byte-compare and
        //   the pairing, making the binding vacuous. So "this VK is output-bound" is trusted
        //   from the issuer's VK, NOT enforced by consensus. This is sound under the threat
        //   model "issuer honest (already trusted for the compliance root), spender adversarial"
        //   — the spender cannot substitute the VK. To ALSO guard against an issuer
        //   registering a non-bound VK (bug or malice), consensus would need a canonical VK
        //   allowlist or circuit-family attestation instead of input count alone — which
        //   re-pins flexibility. That is a trust-model choice for the operator, left open here.
        //
        // Everything else about the circuit — derivation, Merkle depth, hash, extra public
        // inputs at index >= 6 — is invisible to consensus and changes by registering a new
        // VK with NO consensus fork, UP TO the parser cap: GROTH16_MAX_PUBLIC_INPUTS == 8
        // (GROTH16_MAX_PUBLIC_INPUTS_SIZE == 256 bytes). A 9+ field circuit additionally needs
        // that cap raised (a consensus-format change). So free range is 6..8 fields today.
        //
        // NOTE: consensus tightening. If any sub-6-input KYC asset already has spendable
        // UTXOs on a live chain, gate this behind an activation height; pre-activation chains
        // (and genesis-era deployments) can enforce it unconditionally.
        const size_t kyc_pub_input_count = pub_span.size() / groth16::GROTH16_FR_SIZE;
        if (kyc_pub_input_count < assets::GROTH16_HDV1_PUBLIC_INPUTS) {
            LogPrintf("CheckTxInputs: KYC asset %s proof has %zu public inputs, the output-bound interface requires >= %zu — unbound/legacy proofs are rejected\n",
                      aid.ToString(), kyc_pub_input_count, assets::GROTH16_HDV1_PUBLIC_INPUTS);
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-proof-not-hdv1");
        }

        auto element_span = [&](size_t index) -> std::span<const unsigned char> {
            const size_t offset = index * groth16::GROTH16_FR_SIZE;
            if (offset + groth16::GROTH16_FR_SIZE > pub_span.size()) {
                return {};
            }
            return pub_span.subspan(offset, groth16::GROTH16_FR_SIZE);
        };

        const auto chain_elem = element_span(0);
        if (chain_elem.size() != 32 || !std::equal(chain_elem.begin(), chain_elem.end(), chain_separator_bytes.begin())) {
            LogPrintf("CheckTxInputs: chain separator mismatch for asset %s\n", aid.ToString());
            LogPrintf("  Expected: %s\n", HexStr(chain_separator_bytes));
            LogPrintf("  Got:      %s\n", chain_elem.size() == 32 ? HexStr(std::vector<unsigned char>(chain_elem.begin(), chain_elem.end())) : "(wrong size)");
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-chain-mismatch");
        }

        const std::array<unsigned char, 32> expected_asset = Consensus::Uint256ToBytesBE(aid);
        const auto asset_elem = element_span(1);
        if (asset_elem.size() != 32 || !std::equal(asset_elem.begin(), asset_elem.end(), expected_asset.begin())) {
            LogPrintf("CheckTxInputs: asset field mismatch for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-asset-mismatch");
        }

        // ZK Whitelist Hardening: Enforce compliance root commitment (public_inputs[2])
        // Issuer commits a compliance root on-chain; consensus validates proof against it
        const auto root_elem = element_span(2);
        if (root_elem.size() != 32) {
            LogPrintf("CheckTxInputs: root field too short for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-public-inputs-short");
        }

        // Require issuer to have committed a root (enforced from genesis)
        if (policy.compliance_root_commit.IsNull()) {
            LogPrintf("CheckTxInputs: compliance root not set for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-root-not-set");
        }

        // Per-root VK history must be empty (legacy fallback => active VK for historical
        // roots) or exactly lockstep with the root history; anything else is malformed.
        if (!policy.compliance_root_history_vk.empty() &&
            policy.compliance_root_history_vk.size() != policy.compliance_root_history.size()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "asset-registry-malformed");
        }

        // Delegated-asset staleness heartbeat: if the source's ACTIVE root is older than
        // the effective window, freeze the follower until the source rotates. Delegated
        // assets only, and only when a window is set. See REUSABLE_KYC.md §2.4.
        if (policy.delegated && policy.max_root_age > 0 && policy.active_root_activation_height > 0) {
            const int active_age = nSpendHeight - policy.active_root_activation_height;
            if (active_age > static_cast<int>(policy.max_root_age)) {
                LogPrintf("CheckTxInputs: delegated source root stale for asset %s (age=%d > %u)\n",
                          aid.ToString(), active_age, policy.max_root_age);
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-delegate-source-stale");
            }
        }

        // Public inputs are serialized as big-endian field elements.
        const std::array<unsigned char, 32> expected_root = Consensus::Uint256ToBytesBE(policy.compliance_root_commit);

        // Check if proof's root matches the active commitment.
        bool root_valid = std::equal(root_elem.begin(), root_elem.end(), expected_root.begin());

        // VK to verify under: the active VK by default. A historical-root match selects
        // that root's own VK (rolling circuit migration); a null/legacy entry falls back
        // to the active VK.
        uint256 verify_vk = policy.vk_commitment;

        // If active root doesn't match, scan ring buffer for historical roots within freshness window
        if (!root_valid && !policy.compliance_root_history.empty()) {
            for (size_t i = 0; i < policy.compliance_root_history.size(); ++i) {
                const auto& hist = policy.compliance_root_history[i];
                const std::array<unsigned char, 32> hist_root = Consensus::Uint256ToBytesBE(hist.root_commit);
                if (std::equal(root_elem.begin(), root_elem.end(), hist_root.begin())) {
                    // Found matching historical root - check if within max_root_age
                    const int age = nSpendHeight - hist.activation_height;
                    if (age >= 0 && age <= static_cast<int>(policy.max_root_age)) {
                        root_valid = true;
                        if (i < policy.compliance_root_history_vk.size() &&
                            !policy.compliance_root_history_vk[i].IsNull()) {
                            verify_vk = policy.compliance_root_history_vk[i];
                        }
                        break;
                    }
                    // Note: If root found but too old, continue scanning (issuer may have re-rotated to same root)
                }
            }
        }

        if (!root_valid) {
            LogPrintf("CheckTxInputs: root mismatch for asset %s (proof=%s active=%s)\n",
                      aid.ToString(), HexStr(std::vector<unsigned char>(root_elem.begin(), root_elem.end())), HexStr(expected_root));
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-root-mismatch");
        }

        // Fetch the chosen VK now (deferred from above so a historical-root spend
        // verifies under its own VK).
        std::vector<unsigned char> vk_bytes;
        if (!inputs.ReadZkVerifyingKey(verify_vk, vk_bytes)) {
            LogPrintf("CheckTxInputs: verifying key missing for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-vk-missing");
        }
        std::span<const unsigned char> vk_span(vk_bytes.data(), vk_bytes.size());

        std::array<unsigned char, 32> expected_anchor{};
        [[maybe_unused]] bool anchor_present = false;
        if (auto anchor_it = tfr_anchors.find(aid); anchor_it != tfr_anchors.end() && !anchor_it->second.empty()) {
            // anchor_present = true;
            expected_anchor = Consensus::Uint256ToBytesBE(anchor_it->second.front().tfr_commit);
        }

        const auto anchor_elem = element_span(3);
        if (anchor_elem.size() != 32 || !std::equal(anchor_elem.begin(), anchor_elem.end(), expected_anchor.begin())) {
            LogPrintf("CheckTxInputs: anchor mismatch for asset %s\n", aid.ToString());
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-anchor-mismatch");
        }

        // HDv1 output key binding (6-input proofs only).
        // Ensures the proof is bound to the specific Taproot output being spent,
        // preventing proof transfer/reuse across different addresses.
        //
        // For multi-input same-asset spends: verify ALL inputs share the same
        // Taproot x-only key. One proof covers one key; if inputs come from
        // different keys, the proof cannot bind to all of them.
        // Output-key binding — UNIFORM across every conforming circuit. The interface gate
        // above guarantees >= 6 public inputs, and the convention fixes the output key at
        // [4],[5], so there is exactly one binding rule for all KYC circuits (no per-family
        // dispatch, hence nothing that can be "accepted but unbound"). A future circuit with
        // extra fields at index >= 6 still binds here, unchanged.
        const size_t pub_input_count = pub_span.size() / groth16::GROTH16_FR_SIZE;
        {
            // Extract expected key halves from public_inputs[4] and [5]
            const auto key_high_elem = element_span(4);
            const auto key_low_elem = element_span(5);
            if (key_high_elem.size() != 32 || key_low_elem.size() != 32) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-proof-output-mismatch");
            }

            // Check EVERY input for this asset, not just the first
            for (const int input_index : inputs_it->second) {
                const Coin& coin = inputs.AccessCoin(tx.vin[input_index].prevout);
                const CScript& spk = coin.out.scriptPubKey;

                // HDv1 requires Taproot v1 prevout (x-only key in witness program)
                // Taproot v1: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte x-only key>
                if (spk.size() < 34 || spk[0] != 0x51 || spk[1] != 0x20) {
                    LogPrintf("CheckTxInputs: HDv1 proof requires Taproot v1 prevout for input %d, asset %s\n",
                              input_index, aid.ToString());
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-proof-output-not-taproot");
                }

                // Extract x-only key (bytes 2..34 of scriptPubKey)
                const unsigned char* xonly_key = spk.data() + 2;

                // Split 32-byte x-only key into high (bytes 0-15) and low (bytes 16-31) halves.
                // Each half is placed into a 32-byte BE field element with 16 bytes of zero-padding.
                std::array<unsigned char, 32> expected_high{};
                std::array<unsigned char, 32> expected_low{};
                std::memcpy(expected_high.data() + 16, xonly_key, 16);
                std::memcpy(expected_low.data() + 16, xonly_key + 16, 16);

                if (!std::equal(key_high_elem.begin(), key_high_elem.end(), expected_high.begin()) ||
                    !std::equal(key_low_elem.begin(), key_low_elem.end(), expected_low.begin())) {
                    LogPrintf("CheckTxInputs: HDv1 output key mismatch for input %d, asset %s\n",
                              input_index, aid.ToString());
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-proof-output-mismatch");
                }
            }
            LogDebug(BCLog::VALIDATION, "CheckTxInputs: output key binding OK for all %zu inputs of asset %s (%zu public inputs)\n",
                      inputs_it->second.size(), aid.ToString(), pub_input_count);
        }

        // Construct verification context with policy parameters
        groth16::VerificationContext vk_ctx{
            .max_root_age = policy.max_root_age,
            .current_height = nSpendHeight,
            .anchor_commitment = std::nullopt
        };
        // If TFR anchor required, bind to the on-chain commitment
        if ((policy.tfr_flags & assets::TFR_ANCHOR_REQUIRED) != 0) {
            auto anchor_it = tfr_anchors.find(aid);
            if (anchor_it != tfr_anchors.end() && !anchor_it->second.empty()) {
                const auto& anchor = anchor_it->second.front().tfr_commit;
                vk_ctx.anchor_commitment = std::span<const unsigned char>(anchor.begin(), anchor.end());
            }
        }

        // Verify the Groth16 proof with policy-layer binding checks
        const groth16::VerifyError verify_result = groth16::VerifyGroth16WithPolicy(proof_span, pub_span, vk_span, vk_ctx);
        switch (verify_result) {
            case groth16::VerifyError::OK:
                LogDebug(BCLog::VALIDATION, "CheckTxInputs: groth16 verification OK for asset %s\n", aid.ToString());
                break;
            case groth16::VerifyError::InvalidProofFormat:
                LogPrintf("CheckTxInputs: groth16 invalid proof format for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-bad");
            case groth16::VerifyError::InvalidVerifyingKey:
                LogPrintf("CheckTxInputs: groth16 invalid VK for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-vk-invalid");
            case groth16::VerifyError::InvalidPublicInputs:
                LogPrintf("CheckTxInputs: groth16 invalid public inputs for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-public-inputs");
            case groth16::VerifyError::RootTooOld:
                LogPrintf("CheckTxInputs: groth16 root too old for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-epoch-stale");
            case groth16::VerifyError::AnchorMismatch:
                LogPrintf("CheckTxInputs: groth16 anchor mismatch for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "tfr-anchor-mismatch");
            case groth16::VerifyError::OutputKeyMismatch:
                LogPrintf("CheckTxInputs: groth16 output key mismatch for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "kyc-proof-output-mismatch");
            case groth16::VerifyError::PairingFailed:
                LogPrintf("CheckTxInputs: groth16 pairing failed for asset %s\n", aid.ToString());
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-bad");
        }
    }

    if (!IsProofCountWithinLimit(zk_proof_count)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "zk-proof-cap");
    }

    LogDebug(BCLog::VALIDATION, "CheckTxInputs: SUCCESS tx=%s\n", tx.GetHash().ToString());
    return true;
}
