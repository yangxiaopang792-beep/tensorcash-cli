// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <wallet/rpc/api_model_registration.h>
#include <common/args.h>
#include <assets/asset.h>
#include <assets/icu_acceptance_record.h>

#include <algorithm>
#include <cstddef>
#include <vector>

static unsigned int CountOutputMatchOps(const CScript& script)
{
    unsigned int count = 0;
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    while (pc < script.end() && script.GetOp(pc, opcode)) {
        if (opcode == OP_OUTPUTMATCH_NATIVE || opcode == OP_OUTPUTMATCH_ASSET) {
            ++count;
        }
    }
    return count;
}

static bool ScriptContainsOutputMatch(const CScript& script)
{
    return CountOutputMatchOps(script) > 0;
}

static bool TxHasOutputMatch(const CTransaction& tx)
{
    for (const auto& txin : tx.vin) {
        if (ScriptContainsOutputMatch(txin.scriptSig)) return true;
        const CScriptWitness& witness = txin.scriptWitness;
        if (!witness.IsNull() && witness.stack.size() >= 2) {
            const std::vector<unsigned char>& control = witness.stack.back();
            if (!control.empty() && (control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                const std::vector<unsigned char>& leaf = witness.stack[witness.stack.size() - 2];
                CScript script(leaf.begin(), leaf.end());
                if (ScriptContainsOutputMatch(script)) return true;
            }
        }
    }
    return false;
}

// Check if a script contains ML-DSA signature verification opcodes
static bool ScriptContainsMLDSA(const CScript& script)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    while (pc < script.end() && script.GetOp(pc, opcode)) {
        if (opcode == OP_CHECKMLSIG || opcode == OP_CHECKMLSIGVERIFY) {
            return true;
        }
    }
    return false;
}

// Count total bytes that could be ML-DSA signatures in a witness stack
// (items larger than Schnorr max size are assumed to be ML-DSA signatures)
static size_t CountPQBytesInWitnessStack(std::span<const std::vector<unsigned char>> stack)
{
    size_t pq_bytes = 0;
    // Schnorr signatures are max 65 bytes; anything larger is likely ML-DSA
    static constexpr size_t SCHNORR_MAX_SIZE = 65;
    for (const auto& item : stack) {
        if (item.size() > SCHNORR_MAX_SIZE) {
            pq_bytes += item.size();
        }
    }
    return pq_bytes;
}

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kvB.
    // A typical spendable segwit P2WPKH txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kvB.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    size_t nSize = GetSerializeSize(txout);
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    // Note this computation is for spending a Segwit v0 P2WPKH output (a 33 bytes
    // public key + an ECDSA signature). For Segwit v1 Taproot outputs the minimum
    // satisfaction is lower (a single BIP340 signature) but this computation was
    // kept to not further reduce the dust level.
    // See discussion in https://github.com/bitcoin/bitcoin/pull/22779 for details.
    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        // sum the sizes of the parts of a transaction input
        // with 75% segwit discount applied to the script size.
        nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
    } else {
        nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
}

std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        if (IsDust(tx.vout[i], dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

bool IsStandard(const CScript& scriptPubKey, const std::optional<unsigned>& max_datacarrier_bytes, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    } else if (whichType == TxoutType::MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    } else if (whichType == TxoutType::NULL_DATA) {
        if (!max_datacarrier_bytes || scriptPubKey.size() > *max_datacarrier_bytes) {
            return false;
        }
    }

    return true;
}

bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, const CFeeRate& dust_relay_fee, std::string& reason)
{
    // Check if this is a rotation transaction (must check before version, as ROTATION_TX_FLAG is in high bits)
    bool is_rotation = IsRotationTx(tx);

    // For rotation transactions, mask off flag bits when checking version
    uint32_t base_version = is_rotation ? (tx.version & ~CTransaction::ROTATION_TX_FLAG) : tx.version;
    if (base_version > TX_MAX_STANDARD_VERSION || base_version < 1) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    // Rotation transactions get a higher weight limit.
    unsigned int sz = GetTransactionWeight(tx);
    int32_t max_weight = MAX_STANDARD_TX_WEIGHT;
    if (is_rotation) {
        // Apply higher weight limit for rotation transactions
        max_weight = gArgs.GetIntArg("-maxrotationweight", DEFAULT_MAX_ROTATION_TX_WEIGHT);
    }

    if (sz > static_cast<unsigned int>(max_weight)) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin involving only keys is a 15-of-15 P2SH
        // multisig with compressed keys (remember the MAX_SCRIPT_ELEMENT_SIZE byte limit on
        // redeemScript size). That works out to a (15*(33+1))+3=513 byte
        // redeemScript, 513+1+15*(73+1)+3=1627 bytes of scriptSig, which
        // we round off to 1650(MAX_STANDARD_SCRIPTSIG_SIZE) bytes for
        // some minor future-proofing. That's also enough to spend a
        // 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey
        // is not considered standard.
        if (txin.scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    TxoutType whichType;
    size_t asset_outputs = 0;
    size_t tfr_anchor_outputs = 0;
    size_t zk_proof_outputs = 0;
    const bool has_covenant = TxHasOutputMatch(tx);
    // Read policy caps (defaults if not set)
    const size_t max_assets_per_tx = (size_t)std::max<int64_t>(1, gArgs.GetIntArg("-policymaxassetspertx", 64));
    const size_t max_asset_out_size = (size_t)std::max<int64_t>(1, gArgs.GetIntArg("-policymaxassetoutsize", 160));
    // Extra asset dust threshold (policy)
    const CAmount asset_min_dust = gArgs.GetIntArg("-assetmindustbtc", 0);

    for (const CTxOut& txout : tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, max_datacarrier_bytes, whichType)) {
            reason = "scriptpubkey";
            return false;
        }
        // Validate output extension TLV types if present
        if (!txout.vExt.empty()) {
            const auto asset_tag = assets::ParseAssetTag(txout.vExt);
            const auto issuer_reg = assets::ParseIssuerReg(txout.vExt);
            const auto zk_chunk = assets::ParseZkParamsChunk(txout.vExt);
            const auto tfr_anchor = assets::ParseTfrAnchor(txout.vExt);
            const auto icu_chunk = assets::ParseIcuTextChunk(txout.vExt);
            const auto icu_keywrap = assets::ParseIcuKeywrap(txout.vExt);
            const auto zk_proof_payload = assets::ParseZkProofPayload(txout.vExt);
            const auto icu_accept = assets::ParseIcuAcceptanceTLV(txout.vExt);  // 0x40 ICU acceptance record
            // ISSUER_SCALAR (0x11) scalar-feed publication carrier (CFD_GENERALISATION.md §3.1).
            // Relay-standard unconditionally; IsStandardTx is height-agnostic, and the
            // height-gated consensus check (CheckTxInputs / ConnectBlock) is the backstop that
            // rejects a carrier before its activation height, so it can never be mined early.
            const auto issuer_scalar = assets::ParseIssuerScalar(txout.vExt);

            if (!asset_tag && !issuer_reg && !zk_chunk && !tfr_anchor && !icu_chunk && !icu_keywrap && !zk_proof_payload && !icu_accept && !issuer_scalar) {
                reason = "outext";
                return false;
            }

            if (issuer_reg) {
                if (issuer_reg->unlock_fees_sats < static_cast<uint64_t>(txout.nValue)) {
                    reason = "asset-unlock-below-bond-policy";
                    return false;
                }
            }

            if (asset_tag) {
                asset_outputs++;
                CAmount dust_threshold = GetDustThreshold(txout, dust_relay_fee);
                if (asset_min_dust > 0) dust_threshold = std::max<CAmount>(dust_threshold, asset_min_dust);
                if (txout.nValue < dust_threshold) {
                    reason = "asset-dust";
                    return false;
                }
                // ASSET_TAG with ICU_KEYWRAP sub-TLV can be larger (up to 700 bytes)
                if (asset_tag->has_keywrap) {
                    if (txout.vExt.size() > assets::MAX_ICU_KEYWRAP_VEXT_BYTES) {
                        reason = "asset-outext-size";
                        return false;
                    }
                } else {
                    // Regular ASSET_TAG without keywrap: 160-byte limit
                    if (txout.vExt.size() > max_asset_out_size) {
                        reason = "asset-outext-size";
                        return false;
                    }
                }
            }

            if (issuer_reg) {
                // IssuerReg v1 format is 221-232 bytes (deterministic), exempt from policy size limit
                // Consensus validation handles format correctness
            } else if (zk_chunk) {
                // ZK_PARAMS_CHUNK format: type(1) + CompactSize + asset_id(32) + vk_hash(32) + chunk_index(2) + chunk_count(2) + chunk_data(variable)
                // Max chunk_data size is 512 bytes (per spec), so max TLV is ~585 bytes
                const size_t max_zk_chunk_size = 1 + 5 + 32 + 32 + 2 + 2 + 512; // 586 bytes
                if (txout.vExt.size() > max_zk_chunk_size) {
                    reason = "asset-outext-size";
                    return false;
                }
            } else if (icu_chunk) {
                const size_t max_payload_size = 1 + 5 + assets::MAX_ICU_PAYLOAD_BYTES; // type + CompactSize (0xFE + 4 bytes) + payload
                if (txout.vExt.size() > max_payload_size) {
                    reason = "asset-outext-size";
                    return false;
                }
            } else if (icu_keywrap) {
                if (txout.vExt.size() > assets::MAX_ICU_KEYWRAP_VEXT_BYTES) {
                    reason = "asset-outext-size";
                    return false;
                }
            } else if (tfr_anchor) {
                tfr_anchor_outputs++;
            } else if (zk_proof_payload) {
                zk_proof_outputs++;
                // ZK_PROOF_PAYLOAD format: type(1) + CompactSize(payload_len) + payload,
                // where payload = asset_id(32) + CompactSize(proof_len) + proof(192) +
                // CompactSize(inputs_len) + public_inputs.
                //
                // Relay policy should cover the current legacy (128-byte) and HDv1 (192-byte)
                // layouts, plus the parser's consensus-facing upper bound for future layouts.
                const size_t max_zk_proof_payload_payload_size =
                    32 +
                    GetSizeOfCompactSize(assets::GROTH16_PROOF_SIZE) +
                    assets::GROTH16_PROOF_SIZE +
                    GetSizeOfCompactSize(assets::GROTH16_MAX_PUBLIC_INPUTS_SIZE) +
                    assets::GROTH16_MAX_PUBLIC_INPUTS_SIZE;
                const size_t max_zk_proof_payload_size =
                    1 + GetSizeOfCompactSize(max_zk_proof_payload_payload_size) +
                    max_zk_proof_payload_payload_size;
                if (txout.vExt.size() > max_zk_proof_payload_size) {
                    reason = "asset-outext-size";
                    return false;
                }
            } else if (icu_accept) {
                // ICU acceptance record (0x40): generous relay cap (consensus only enforces the 16 KiB
                // per-output vExt hard limit); fits the fixed fields + many body_refs + a secp signature.
                if (txout.vExt.size() > assets::MAX_ICU_ACCEPTANCE_VEXT_BYTES) {
                    reason = "asset-outext-size";
                    return false;
                }
            } else if (!asset_tag && txout.vExt.size() > max_asset_out_size) {
                // Catch-all for unknown TLV types (asset_tag already checked above)
                reason = "asset-outext-size";
                return false;
            }
        }

        if (has_covenant && !txout.HasAssetTLV() && !txout.scriptPubKey.IsUnspendable()) {
            CAmount dust_threshold = GetDustThreshold(txout, dust_relay_fee);
            if (txout.nValue < dust_threshold) {
                reason = "covenant-native-dust";
                return false;
            }
        }

        if (whichType == TxoutType::NULL_DATA)
            nDataOut++;
        else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
            reason = "bare-multisig";
            return false;
        }
    }
    // Cap number of AssetTag outputs
    if (asset_outputs > max_assets_per_tx) {
        reason = "assets-per-tx";
        return false;
    }

    if (TxHasOutputMatch(tx) && tx.vout.size() > MAX_COVENANT_TX_OUTPUTS) {
        reason = "too-many-covenant-outputs";
        return false;
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
        reason = "dust";
        return false;
    }

    // only one OP_RETURN txout is permitted for non model deposit/commit transactions
    if (nDataOut > 1) {
        const bool is_model_tx = (tx.version == static_cast<int32_t>(Consensus::MODEL_REGISTER_DEPOSIT_TX_VERSION)) ||
                                 (tx.version == static_cast<int32_t>(Consensus::MODEL_REGISTER_COMMIT_TX_VERSION)) ||
                                 (tx.version == static_cast<int32_t>(Consensus::MODEL_REGISTER_BURN_TX_VERSION)) ||
                                 (tx.version == static_cast<int32_t>(Consensus::MODEL_ACCUSATION_TX_VERSION)) ||
                                 (tx.version == static_cast<int32_t>(Consensus::MODEL_CHALLENGE_COMMIT_TX_VERSION));
        const bool is_dual_protection_metadata =
            nDataOut == 2 &&
            tfr_anchor_outputs == 1 &&
            zk_proof_outputs == 1;
        if ((!is_model_tx && !is_dual_protection_metadata) || nDataOut > MAX_OP_RETURN_COUNT) {
            reason = "multi-op-return";
            return false;
        }
    }

    return true;
}

/**
 * Check transaction inputs.
 *
 * This does three things:
 *  * Prevents mempool acceptance of spends of future
 *    segwit versions we don't know how to validate
 *  * Mitigates a potential denial-of-service attack with
 *    P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations.
 *  * Prevents spends of unknown/irregular scriptPubKeys,
 *    which mitigates potential denial-of-service attacks
 *    involving expensive scripts and helps reserve them
 *    as potential new upgrade hooks.
 *
 * Note that only the non-witness portion of the transaction is checked here.
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        unsigned int outputmatch_total = CountOutputMatchOps(prev.scriptPubKey);
        if (outputmatch_total > MAX_OUTPUTMATCH_PER_INPUT) {
            return false;
        }

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD) {
            return false;
        } else if (whichType == TxoutType::WITNESS_UNKNOWN) {
            int witnessversion = 0;
            std::vector<unsigned char> witnessprogram;
            if (!prev.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
                return false;
            }
            // Permit Taproot v2 (script-only) spends while keeping other future witness
            // versions non-standard so they must be explicitly deployed.
            if (!(witnessversion == 2 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE)) {
                return false;
            }
        } else if (whichType == TxoutType::SCRIPTHASH) {
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                return false;
            }
            outputmatch_total += CountOutputMatchOps(subscript);
            if (outputmatch_total > MAX_OUTPUTMATCH_PER_INPUT) {
                return false;
            }
        }
    }

    return true;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;
        unsigned int outputmatch_total = CountOutputMatchOps(prevScript);
        if (outputmatch_total > MAX_OUTPUTMATCH_PER_INPUT) {
            return false;
        }

        // witness stuffing detected
        if (prevScript.IsPayToAnchor()) {
            return false;
        }

        bool p2sh = false;
        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
            p2sh = true;
            outputmatch_total += CountOutputMatchOps(prevScript);
            if (outputmatch_total > MAX_OUTPUTMATCH_PER_INPUT) {
                return false;
            }
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }

        // Check policy limits for Taproot spends:
        // - MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE limit for stack item size
        // - No annexes
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            // Taproot spend (non-P2SH-wrapped, version 1, witness program size 32; see BIP 341)
            std::span stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are nonstandard as long as no semantics are defined for them.
                return false;
            }
            if (stack.size() >= 2) {
                // Script path spend (2 or more stack elements after removing optional annex)
                const size_t script_index = stack.size() - 2;
                std::vector<unsigned char> leaf_script_bytes(stack[script_index].begin(), stack[script_index].end());
                const auto& control_block = SpanPopBack(stack);
                SpanPopBack(stack); // Remove script
                CScript leaf_script(leaf_script_bytes.begin(), leaf_script_bytes.end());
                outputmatch_total += CountOutputMatchOps(leaf_script);
                if (outputmatch_total > MAX_OUTPUTMATCH_PER_INPUT) {
                    return false;
                }
                if (control_block.empty()) return false; // Empty control block is invalid
                if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Leaf version 0xc0 (aka Tapscript, see BIP 342)

                    // Policy: ML-DSA opcodes are only allowed in witness v2 (PQ-enabled Taproot)
                    if (ScriptContainsMLDSA(leaf_script)) {
                        return false;
                    }

                    // Policy: enforce per-input PQ byte cap to prevent DoS
                    if (CountPQBytesInWitnessStack(stack) > MAX_STANDARD_PQ_BYTES_PER_INPUT) {
                        return false;
                    }

                    for (const auto& item : stack) {
                        if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) return false;
                    }
                }
            } else if (stack.size() == 1) {
                // Key path spend (1 stack element after removing optional annex)
                // (no policy rules apply)
            } else {
                // 0 stack elements; this is already invalid by consensus rules
                return false;
            }
        } else if (witnessversion == 2 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            // Taproot v2 script-only (non-P2SH-wrapped, version 2, witness program size 32)
            std::span stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are nonstandard as long as no semantics are defined for them.
                return false;
            }
            if (stack.size() >= 2) {
                const size_t script_index = stack.size() - 2;
                std::vector<unsigned char> leaf_script_bytes(stack[script_index].begin(), stack[script_index].end());
                const auto& control_block = SpanPopBack(stack);
                SpanPopBack(stack); // Remove script
                CScript leaf_script(leaf_script_bytes.begin(), leaf_script_bytes.end());
                outputmatch_total += CountOutputMatchOps(leaf_script);
                if (outputmatch_total > MAX_OUTPUTMATCH_PER_INPUT) {
                    return false;
                }
                if (control_block.empty()) return false; // Empty control block is invalid
                if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Taproot v2 allows larger stack items for PQ signatures

                    // Policy: enforce per-input PQ byte cap to prevent DoS
                    if (CountPQBytesInWitnessStack(stack) > MAX_STANDARD_PQ_BYTES_PER_INPUT) {
                        return false;
                    }

                    for (const auto& item : stack) {
                        if (item.size() > MAX_STANDARD_TAPSCRIPT_V2_STACK_ITEM_SIZE) return false;
                    }
                }
            } else {
                // Key path spend (stack.size() == 1) or malformed witness - nonstandard
                return false;
            }
        }
    }
    return true;
}

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return (std::max(nWeight, nSigOpCost * bytes_per_sigop) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost, bytes_per_sigop);
}

int64_t GetVirtualTransactionInputSize(const CTxIn& txin, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(txin), nSigOpCost, bytes_per_sigop);
}
