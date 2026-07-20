// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MINING_H
#define BITCOIN_TEST_UTIL_MINING_H

#include <node/miner.h>

#include <memory>
#include <string>
#include <vector>

class CBlock;
class CChainParams;
class ChainstateManager;
class COutPoint;
class CScript;
struct CMutableTransaction;
namespace Consensus {
struct Params;
} // namespace Consensus
namespace node {
struct NodeContext;
} // namespace node

/** Create a blockchain, starting from genesis */
std::vector<std::shared_ptr<CBlock>> CreateBlockChain(size_t total_height, const CChainParams& params);

/** Returns the generated coin */
COutPoint MineBlock(const node::NodeContext&,
                    const node::BlockAssembler::Options& assembler_options);

/**
 * Returns the generated coin (or Null if the block was invalid).
 * It is recommended to call RegenerateCommitments before mining the block to avoid merkle tree mismatches.
 **/
COutPoint MineBlock(const node::NodeContext&, std::shared_ptr<CBlock>& block);

/**
 * Returns the generated coin (or Null if the block was invalid).
 */
COutPoint ProcessBlock(const node::NodeContext&, const std::shared_ptr<CBlock>& block);

/** Prepare a block to be mined */
std::shared_ptr<CBlock> PrepareBlock(const node::NodeContext&);
std::shared_ptr<CBlock> PrepareBlock(const node::NodeContext& node,
                                     const node::BlockAssembler::Options& assembler_options);
std::shared_ptr<CBlock> PrepareBlock(const node::NodeContext& node,
                                     const CScript& coinbase_scriptPubKey);

/** RPC-like helper function, returns the generated coin */
COutPoint generatetoaddress(const node::NodeContext&, const std::string& address);

// Update VDF-derived fields for a test block using the active chain.
void UpdateTestBlockVdf(CBlock& block, ChainstateManager& chainman);

// Offline variant for synthetic chains constructed without a ChainstateManager.
void UpdateTestBlockVdf(CBlock& block, const CBlock* prev_block, int next_height, const Consensus::Params& consensus);

// Offline variant using only the previous cumulative tick and next height.
void UpdateTestBlockVdf(CBlock& block, uint64_t prev_cumulative_tick, int next_height, const Consensus::Params& consensus);

// TensorCash test helpers

// Centralize Tensor header defaults used by tests that hand-construct headers/blocks.
template <typename BlockOrHeader>
inline void InitializeTensorHeader(BlockOrHeader& h)
{
    h.nAdjBits = h.nBits;
}

// Create a valid block using BlockAssembler, append extra txs, regenerate
// commitments, set nAdjBits and mine with deterministic PoW.
// Note: prefer this helper over hand-populating header fields to avoid drift
// from production code paths.
CBlock CreateTensorBlock(node::NodeContext& node,
                         const std::vector<CMutableTransaction>& extra_txs,
                         const CScript& coinbase_script);

// Convenience overload: no extra txs, default coinbase OP_TRUE.
CBlock CreateTensorBlock(node::NodeContext& node);

#endif // BITCOIN_TEST_UTIL_MINING_H
