#ifndef TENSORCASH_ASSETS_SIGHASH_UTILS_H
#define TENSORCASH_ASSETS_SIGHASH_UTILS_H

#include <algorithm>
#include <optional>
#include <vector>

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>

namespace assets {

/**
 * Extract the sighash byte encoded in a signature-like witness or scriptSig element.
 *
 * Recognised encodings:
 *   - DER-encoded ECDSA signatures (9-73 bytes): the trailing byte contains the sighash.
 *   - BIP341 Schnorr signatures with explicit sighash (65 bytes): the trailing byte contains the sighash.
 *   - BIP341 Schnorr signatures with implicit SIGHASH_DEFAULT (64 bytes, witness context only).
 *
 * @param element       Stack element to inspect.
 * @param is_witness    True when the element originates from a witness stack (enables Taproot handling).
 * @return              The sighash byte if the element matches a recognised signature encoding; std::nullopt otherwise.
 */
inline std::optional<unsigned char> ExtractSignatureSighash(const std::vector<unsigned char>& element,
                                                            bool is_witness)
{
    if (element.empty()) {
        return std::nullopt;
    }

    if (element.size() >= 9 && element.size() <= 73) {
        if (CheckSignatureEncoding(element, SCRIPT_VERIFY_STRICTENC, nullptr)) {
            return element.back();
        }
    }

    if (is_witness) {
        if (element.size() == 65) {
            const unsigned char sighash = element.back();
            const unsigned char base = sighash & 0x1f;
            if (base == SIGHASH_ALL || base == SIGHASH_NONE || base == SIGHASH_SINGLE || base == SIGHASH_DEFAULT) {
                const bool non_zero_payload = std::any_of(element.begin(), element.end() - 1,
                                                         [](unsigned char b) { return b != 0; });
                if (non_zero_payload) {
                    return sighash;
                }
            }
        }

        if (element.size() == 64) {
            const bool non_zero_payload = std::any_of(element.begin(), element.end(),
                                                      [](unsigned char b) { return b != 0; });
            if (non_zero_payload) {
                return static_cast<unsigned char>(SIGHASH_DEFAULT);
            }
        }
    }

    return std::nullopt;
}

/**
 * Determine whether a sighash byte commits to all inputs/outputs (no ANYONECANPAY, ALL/DEFAULT base).
 */
inline bool IsOutputBindingSighash(unsigned char sighash)
{
    if ((sighash & SIGHASH_ANYONECANPAY) != 0) {
        return false;
    }
    const unsigned char base = sighash & 0x1f;
    return base == SIGHASH_ALL || base == SIGHASH_DEFAULT;
}

/**
 * Sighash acceptable on a rotation BALLOT input whose paired self-bounce output has already
 * been validated (matching asset id + amount + proposal_hash at the same index). On top of
 * the strict output-binding sighashes, a ballot may use SIGHASH_SINGLE|ANYONECANPAY, which
 * commits this input to its own output (index i) and enables parallel signing. Everything
 * weaker — SIGHASH_NONE (with or without ANYONECANPAY), bare SIGHASH_SINGLE, ALL|ANYONECANPAY
 * — is rejected. Caller MUST have validated the paired output before granting this relaxation.
 */
inline bool IsBallotSighash(unsigned char sighash)
{
    if (IsOutputBindingSighash(sighash)) {
        return true;
    }
    const unsigned char base = sighash & 0x1f;
    const bool acp = (sighash & SIGHASH_ANYONECANPAY) != 0;
    return base == SIGHASH_SINGLE && acp;
}

struct SighashScanResult {
    bool ok{true};
    bool saw_signature{false};
};

/**
 * Scan all signature-like elements in a transaction input and apply a predicate to the extracted sighash bytes.
 *
 * The scan inspects both scriptSig (legacy/P2SH context) and scriptWitness (segwit/Taproot context). For Taproot
 * inputs, an optional annex (first witness element beginning with 0x50) is skipped per BIP341.
 *
 * @param txin        Input to scan.
 * @param predicate   Functor invoked for each extracted sighash byte; returning false marks the scan as failed.
 * @return            SighashScanResult with `saw_signature` set when any signature is encountered and `ok` indicating
 *                    whether all encountered signatures satisfied the predicate.
 */
template <typename Predicate>
inline SighashScanResult ScanInputSighashes(const CTxIn& txin, Predicate&& predicate)
{
    SighashScanResult result;

    auto process_element = [&](const std::vector<unsigned char>& element, bool is_witness) -> bool {
        const std::optional<unsigned char> sighash_opt = ExtractSignatureSighash(element, is_witness);
        if (!sighash_opt.has_value()) {
            return true;
        }
        result.saw_signature = true;
        if (!predicate(*sighash_opt)) {
            result.ok = false;
            return false;
        }
        return true;
    };

    if (!txin.scriptSig.empty()) {
        CScript::const_iterator it = txin.scriptSig.begin();
        opcodetype opcode;
        std::vector<unsigned char> pushed;
        while (txin.scriptSig.GetOp(it, opcode, pushed)) {
            if (opcode <= OP_PUSHDATA4) {
                if (!process_element(pushed, /*is_witness=*/false)) {
                    return result;
                }
            }
        }
    }

    if (!txin.scriptWitness.IsNull()) {
        size_t start_index = 0;
        if (!txin.scriptWitness.stack.empty() && txin.scriptWitness.stack.size() > 1) {
            const auto& first = txin.scriptWitness.stack.front();
            if (!first.empty() && first.front() == 0x50) {
                start_index = 1; // Skip Taproot annex per BIP341.
            }
        }
        for (size_t i = start_index; i < txin.scriptWitness.stack.size(); ++i) {
            if (!process_element(txin.scriptWitness.stack[i], /*is_witness=*/true)) {
                return result;
            }
        }
    }

    return result;
}

} // namespace assets

#endif // TENSORCASH_ASSETS_SIGHASH_UTILS_H
