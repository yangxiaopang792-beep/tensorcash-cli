// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ONION_DIVERSITY_H
#define BITCOIN_ONION_DIVERSITY_H

#include <chain.h>
#include <uint256.h>

#include <cstdint>
#include <string>

/**
 * Convert the first tag_len base32 characters derived from a block hash.
 * Uses the same base32 charset as .onion addresses.
 */
std::string BlockHashToBase32Tag(const uint256& hash, size_t tag_len);

/**
 * Check whether a vanity .onion address contains a freshness tag matching
 * a recent block hash within [tip_height - window, tip_height].
 *
 * This overload walks the header chain backwards from the given tip,
 * so it works even during IBD when the validated block chain is far behind.
 * Block hashes are derived from headers and don't require block data.
 *
 * @param onion_addr   Full .onion hostname (without port)
 * @param tip          Best known header (caller must hold cs_main)
 * @param window       Number of headers to scan backwards from tip
 * @param prefix       Expected vanity prefix (e.g. "tensorc")
 * @param tag_len      Length of the freshness tag after the prefix
 * @return true if the onion address starts with prefix and the following
 *         tag_len characters match a base32 tag from a header in the window
 */
bool CheckOnionFreshness(const std::string& onion_addr, const CBlockIndex* tip,
                         int window, const std::string& prefix, size_t tag_len);

/**
 * Derive a uint64_t diversity key from a full .onion address.
 * The high bit is always set, guaranteeing no collision with ASN values
 * (which are uint32_t, always in [0, 2^32)).
 */
uint64_t OnionToDiversityKey(const std::string& onion_addr);

#endif // BITCOIN_ONION_DIVERSITY_H
