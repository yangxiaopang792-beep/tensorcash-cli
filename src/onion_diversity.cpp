// Copyright (c) 2024-present The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <onion_diversity.h>

#include <crypto/siphash.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cmath>
#include <cstring>

std::string BlockHashToBase32Tag(const uint256& hash, size_t tag_len)
{
    // IMPORTANT byte-order contract: We encode from uint256::data() which is the
    // internal little-endian byte array, NOT the human-readable RPC hex string
    // (which is big-endian / reversed). Phase 2 vanity generators must use the
    // same byte ordering: take raw block hash bytes and base32-encode them.
    //
    // Number of raw bytes needed to produce tag_len base32 characters.
    // Each base32 char encodes 5 bits, so we need ceil(tag_len * 5 / 8) bytes.
    size_t raw_bytes = (tag_len * 5 + 7) / 8;

    // Clamp to available hash bytes (32)
    raw_bytes = std::min(raw_bytes, size_t{32});

    std::span<const unsigned char> input(hash.data(), raw_bytes);
    std::string encoded = EncodeBase32(input, /*pad=*/false);

    // Truncate to requested tag length
    if (encoded.size() > tag_len) {
        encoded.resize(tag_len);
    }
    return encoded;
}

bool CheckOnionFreshness(const std::string& onion_addr, const CBlockIndex* tip,
                         int window, const std::string& prefix, size_t tag_len)
{
    if (!tip) return false;

    // Must start with the vanity prefix
    if (onion_addr.size() < prefix.size() + tag_len) return false;
    if (onion_addr.compare(0, prefix.size(), prefix) != 0) return false;

    // Extract the freshness tag from the onion address
    std::string addr_tag = onion_addr.substr(prefix.size(), tag_len);

    // Walk backwards from the best known header (not the validated chain).
    // Block hashes are computed from headers and don't require block data,
    // so this works during IBD when the validated chain is far behind.
    const CBlockIndex* pindex = tip;
    for (int i = 0; i < window && pindex; ++i, pindex = pindex->pprev) {
        std::string block_tag = BlockHashToBase32Tag(pindex->GetBlockHash(), tag_len);
        if (block_tag == addr_tag) {
            return true;
        }
    }
    return false;
}

uint64_t OnionToDiversityKey(const std::string& onion_addr)
{
    // Use SipHash with fixed keys to hash the onion address string
    CSipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    hasher.Write(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(onion_addr.data()),
        onion_addr.size()));
    uint64_t h = hasher.Finalize();

    // Set high bit to guarantee no collision with ASN values (uint32_t range)
    return (1ULL << 63) | (h & 0x7FFFFFFFFFFFFFFFULL);
}
