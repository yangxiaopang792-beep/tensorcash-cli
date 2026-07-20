// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHash() const
{
    DataStream ss;
    ss << nVersion;
    ss << hashPrevBlock;
    ss << hashMerkleRoot;
    ss << nTime;
    ss << nAdjBits;
    ss << nNonce;

    ss << nBits;
    ss << hashPoW;
    return Hash(ss);
}

uint256 CBlockHeader::GetShortHash() const
{
    DataStream ss;
    ss << nVersion;
    ss << hashPrevBlock;
    ss << hashMerkleRoot;
    ss << nTime;
    ss << nAdjBits;
    ss << nNonce;

    return Hash(ss);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, hashShort=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nAdjBits=%08x, nNonce=%u, hashPoWblob=%s, flags=%08x, model=%s, ticks=%d, vtx=%u)\n",
        GetHash().ToString(),
        GetShortHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nAdjBits, nNonce,
        hashPoW.ToString(),
        flags,
        pow.model_identifier,
        cumulative_tick,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
