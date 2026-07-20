// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_BIP322_H
#define BITCOIN_RPC_BIP322_H

#include <string>

/** Verify a BIP-322 signature for `message` against `address`. Returns false on
 *  any decode/verification failure. Used by the ICU acceptance verify RPC. */
bool VerifyBIP322Signature(const std::string& address, const std::string& signature, const std::string& message);

#endif // BITCOIN_RPC_BIP322_H
