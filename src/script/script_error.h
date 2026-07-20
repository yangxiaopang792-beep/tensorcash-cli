// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_ERROR_H
#define BITCOIN_SCRIPT_SCRIPT_ERROR_H

#include <string>

typedef enum ScriptError_t
{
    SCRIPT_ERR_OK = 0,
    SCRIPT_ERR_UNKNOWN_ERROR,
    SCRIPT_ERR_EVAL_FALSE,
    SCRIPT_ERR_OP_RETURN,

    /* Max sizes */
    SCRIPT_ERR_SCRIPT_SIZE,
    SCRIPT_ERR_PUSH_SIZE,
    SCRIPT_ERR_OP_COUNT,
    SCRIPT_ERR_STACK_SIZE,
    SCRIPT_ERR_SIG_COUNT,
    SCRIPT_ERR_PUBKEY_COUNT,

    /* Failed verify operations */
    SCRIPT_ERR_VERIFY,
    SCRIPT_ERR_EQUALVERIFY,
    SCRIPT_ERR_CHECKMULTISIGVERIFY,
    SCRIPT_ERR_CHECKSIGVERIFY,
    SCRIPT_ERR_NUMEQUALVERIFY,

    /* Logical/Format/Canonical errors */
    SCRIPT_ERR_BAD_OPCODE,
    SCRIPT_ERR_DISABLED_OPCODE,
    SCRIPT_ERR_INVALID_STACK_OPERATION,
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION,
    SCRIPT_ERR_UNBALANCED_CONDITIONAL,

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    SCRIPT_ERR_NEGATIVE_LOCKTIME,
    SCRIPT_ERR_UNSATISFIED_LOCKTIME,

    /* Malleability */
    SCRIPT_ERR_SIG_HASHTYPE,
    SCRIPT_ERR_SIG_DER,
    SCRIPT_ERR_MINIMALDATA,
    SCRIPT_ERR_SIG_PUSHONLY,
    SCRIPT_ERR_SIG_HIGH_S,
    SCRIPT_ERR_SIG_NULLDUMMY,
    SCRIPT_ERR_PUBKEYTYPE,
    SCRIPT_ERR_CLEANSTACK,
    SCRIPT_ERR_MINIMALIF,
    SCRIPT_ERR_SIG_NULLFAIL,

    /* softfork safeness */
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_ERR_DISCOURAGE_OP_SUCCESS,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,

    /* segregated witness */
    SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH,
    SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY,
    SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
    SCRIPT_ERR_WITNESS_MALLEATED,
    SCRIPT_ERR_WITNESS_MALLEATED_P2SH,
    SCRIPT_ERR_WITNESS_UNEXPECTED,
    SCRIPT_ERR_WITNESS_PUBKEYTYPE,

    /* Taproot */
    SCRIPT_ERR_SCHNORR_SIG_SIZE,
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE,
    SCRIPT_ERR_SCHNORR_SIG,
    SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE,
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT,
    SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG,
    SCRIPT_ERR_TAPSCRIPT_MINIMALIF,
    SCRIPT_ERR_TAPSCRIPT_ONLY,
    SCRIPT_ERR_INVALID_OPERAND_SIZE,
    SCRIPT_ERR_AMOUNT_OUT_OF_RANGE,

    /* Taproot script-only v2 */
    SCRIPT_ERR_TAPROOT_KEYPATH_DISABLED,

    /* Constant scriptCode */
    SCRIPT_ERR_OP_CODESEPARATOR,
    SCRIPT_ERR_SIG_FINDANDDELETE,

    /* Post-quantum ML-DSA */
    SCRIPT_ERR_MLDSA_ENCODING,
    SCRIPT_ERR_MLDSA_VERIFY,

    /* Difficulty-derivative covenant (OP_NBITS_AT / OP_DIFFCFD_SETTLE) */
    SCRIPT_ERR_DIFFCFD_CONTEXT,   // missing fixing context, or executed under the wrong witness version
    SCRIPT_ERR_DIFFCFD_HEIGHT,    // fixing height out of range / not yet final / unresolvable
    SCRIPT_ERR_DIFFCFD_ENCODING,  // bad operand length, non-canonical strike, or bad loss_direction byte
    SCRIPT_ERR_DIFFCFD_TERMS,     // invalid committed terms (lambda_q == 0, vault_im below floor)
    SCRIPT_ERR_DIFFCFD_OUTPUTS,   // required settlement output(s) absent/mismatched
    SCRIPT_ERR_DIFFCFD_AMOUNT,    // spent input amount != committed vault_im

    /* Scalar-derivative covenant (OP_SCALAR_CFD_SETTLE, CFD_GENERALISATION.md §2.3) */
    SCRIPT_ERR_SCALARCFD_CONTEXT,    // missing fixing snapshot, wrong witness version, or no output context
    SCRIPT_ERR_SCALARCFD_ENCODING,   // bad operand length/encoding, non-canonical strike, or bad enum byte
    SCRIPT_ERR_SCALARCFD_FIXING,     // no resolvable scalar fixing (still pending, or unparsed leaf -> fail-closed)
    SCRIPT_ERR_SCALARCFD_TERMS,      // invalid committed terms (lambda_q == 0, vault_im below floor)
    SCRIPT_ERR_SCALARCFD_COLLATERAL, // collateral asset fails the consensus safety gate (§5.1)
    SCRIPT_ERR_SCALARCFD_AMOUNT,     // spent input != committed vault_im (native or asset)
    SCRIPT_ERR_SCALARCFD_OUTPUTS,    // required settlement output(s) absent/mismatched

    SCRIPT_ERR_ERROR_COUNT
} ScriptError;

#define SCRIPT_ERR_LAST SCRIPT_ERR_ERROR_COUNT

std::string ScriptErrorString(const ScriptError error);

#endif // BITCOIN_SCRIPT_SCRIPT_ERROR_H
