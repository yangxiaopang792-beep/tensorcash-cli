// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

namespace {
// Computes min(pow_limit, floor(old_target * actual / target)) without 256-bit
// overflow, by dividing before multiplying. Identical to the naive
// `old_target * actual / target` in every case where that product fits in 256 bits;
// it additionally stays correct when old_target is near pow_limit (tensor mainnet
// powLimit ~2^255, so base targets are ~2^247), where the naive multiply wraps.
// Shared by CalculateNextWorkRequired and PermittedDifficultyTransition so mining
// and validation can never disagree on the retarget.
arith_uint256 RetargetSafe(const arith_uint256& old_target, uint64_t actual,
                           uint64_t target, const arith_uint256& pow_limit)
{
    if (target == 0) return pow_limit; // consensus param is never 0; defensive only

    const arith_uint256 target_b = arith_uint256(target);
    arith_uint256 q = old_target;
    q /= target_b;                      // q = floor(old_target / target)
    arith_uint256 r = old_target;
    r -= q * target_b;                  // r = old_target mod target  (0 <= r < target)

    // If q*actual would exceed pow_limit it would also overflow; the true result is
    // capped at pow_limit anyway, so saturate before the multiply.
    if (actual != 0 && q > pow_limit / actual) {
        return pow_limit;
    }

    arith_uint256 out = q;
    out *= actual;                      // q*actual <= pow_limit, cannot wrap

    // floor(old*actual/target) = q*actual + floor(r*actual/target). r < target and
    // actual <= 4*target, so r*actual fits in 128 bits comfortably.
    const uint64_t r64 = r.GetLow64();
    unsigned __int128 extra = (static_cast<unsigned __int128>(r64) * actual) / target;
    if (extra > 0) {
        if (out > pow_limit - (uint64_t)extra) return pow_limit;
        out += (uint64_t)extra;
    }
    return out > pow_limit ? pow_limit : out;
}
} // namespace

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    // std::cout << "=== CalculateNextWorkRequired_New DEBUG ===" << std::endl;
    // std::cout << "Last nHeight : " << pindexLast->nHeight << std::endl;
    // std::cout << "Last nBits : " << pindexLast->nBits << std::endl;
    // std::cout << "Last nAdjBits : " << pindexLast->nAdjBits << std::endl;
    // std::cout << "nActualTimespan original: " << nActualTimespan << std::endl; 
    
    
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    // std::cout << "nActualTimespan 1st modif: " << nActualTimespan << std::endl; 
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;
    // std::cout << "nActualTimespan 2nd modif: " << nActualTimespan << std::endl; 
    
    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    // std::cout << "New bnPowLimit : " << bnPowLimit.GetCompact() << std::endl; 
    // std::cout << "New bnPowLimit : " << ArithToUint256(bnPowLimit).ToString() << std::endl; 
    

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    // std::cout << "bnNew origin : " << bnNew.GetCompact() << std::endl; 
    // std::cout << "bnNew origin : " << ArithToUint256(bnNew).ToString() << std::endl; 
    
    // Overflow-safe retarget: multiply, divide and powLimit-cap are all performed
    // inside RetargetSafe (divide-first) so base targets near powLimit cannot wrap.
    bnNew = RetargetSafe(bnNew, static_cast<uint64_t>(nActualTimespan),
                         static_cast<uint64_t>(params.nPowTargetTimespan), bnPowLimit);

    // std::cout << "New nBits : " << bnNew.GetCompact() << std::endl; 
    // std::cout << "New nBits : " << ArithToUint256(bnNew).ToString() << std::endl; 
    // std::cout << "=== CalculateNextWorkRequired Finished ===" << std::endl;
    

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible. Uses the SAME overflow-safe
        // helper as CalculateNextWorkRequired — otherwise validation and mining can
        // disagree on tensor mainnet, where base targets approach powLimit and the
        // naive multiply wraps.
        arith_uint256 old_target;
        old_target.SetCompact(old_nbits);
        arith_uint256 largest_difficulty_target = RetargetSafe(
            old_target, static_cast<uint64_t>(largest_timespan),
            static_cast<uint64_t>(params.nPowTargetTimespan), pow_limit);

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible (same overflow-safe helper):
        arith_uint256 smallest_difficulty_target = RetargetSafe(
            old_target, static_cast<uint64_t>(smallest_timespan),
            static_cast<uint64_t>(params.nPowTargetTimespan), pow_limit);

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    // std::cout << "=== CheckProofOfWorkImpl DEBUG ===" << std::endl;
    // std::cout << "hash : " << hash.ToString() << std::endl;
    // std::cout << "nBits : " << nBits << std::endl; 
    // std::cout << "params.powLimit : " << params.powLimit.ToString() << std::endl; 
    
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;
    
    // std::cout << "Derived target: " << bnTarget->ToString() << std::endl;
    
    arith_uint256 hashArith = UintToArith256(hash);
    // std::cout << "Hash as arith: " << hashArith.ToString() << std::endl;
    // std::cout << "Hash > Target: " << (hashArith > *bnTarget) << std::endl;
    
    // Check proof of work matches claimed amount
    if (hashArith > *bnTarget) return false;
    
    // std::cout << "PoW check PASSED" << std::endl;
    return true;
}
