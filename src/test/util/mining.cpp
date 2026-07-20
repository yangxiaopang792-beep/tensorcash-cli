// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/mining.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <script/script.h>
#include <key_io.h>
#include <node/context.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/proofblob.h>
#include <primitives/transaction.h>
#include <test/util/script.h>
#include <modeldb.h>
#include <sync.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>
#include <vdf/VdfGenerate.h>

#include <algorithm>

using node::BlockAssembler;
using node::NodeContext;

namespace {

constexpr uint64_t DEFAULT_VDF_TICK{10};

void MaybePopulateVdf(CBlock& block, const Consensus::Params& consensus, int next_height)
{
    if (consensus.IsVdfVdfVerifyActive(next_height)) {
        if (block.pow.tick == 0) {
            block.pow.tick = DEFAULT_VDF_TICK;
        }
        block.pow.vdf = vdf::GenerateProofForTesting(block.hashPrevBlock, block.pow.tick, 1024);
    } else {
        block.pow.tick = 0;
        block.pow.vdf.clear();
    }
}

} // namespace

void UpdateTestBlockVdf(CBlock& block, ChainstateManager& chainman)
{
    const Consensus::Params& consensus = chainman.GetConsensus();
    const CBlockIndex* prev_index = nullptr;
    {
        LOCK(cs_main);
        prev_index = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    }
    const int next_height = prev_index ? (prev_index->nHeight + 1) : 1;

    uint64_t prev_cumulative_tick = 0;
    if (prev_index != nullptr) {
        CBlock prev_block;
        if (chainman.m_blockman.ReadBlock(prev_block, *prev_index)) {
            prev_cumulative_tick = prev_block.cumulative_tick;
        }
    }

    UpdateTestBlockVdf(block, prev_cumulative_tick, next_height, consensus);
}

void UpdateTestBlockVdf(CBlock& block, const CBlock* prev_block, int next_height, const Consensus::Params& consensus)
{
    const uint64_t prev_cumulative_tick = prev_block ? prev_block->cumulative_tick : 0;
    UpdateTestBlockVdf(block, prev_cumulative_tick, next_height, consensus);
}

void UpdateTestBlockVdf(CBlock& block, uint64_t prev_cumulative_tick, int next_height, const Consensus::Params& consensus)
{
    MaybePopulateVdf(block, consensus, next_height);

    block.cumulative_tick = prev_cumulative_tick + block.pow.tick;

    const bool use_merkle = consensus.IsVdfSpvActive(next_height);
    block.hashPoW = block.pow.GetCommitment(use_merkle);
}

COutPoint generatetoaddress(const NodeContext& node, const std::string& address)
{
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    BlockAssembler::Options assembler_options;
    assembler_options.coinbase_output_script = GetScriptForDestination(dest);

    return MineBlock(node, assembler_options);
}

std::vector<std::shared_ptr<CBlock>> CreateBlockChain(size_t total_height, const CChainParams& params)
{
    std::vector<std::shared_ptr<CBlock>> ret{total_height};
    auto time{params.GenesisBlock().nTime};
    const CBlock genesis{params.GenesisBlock()};
    // NOTE: here `height` does not correspond to the block height but the block height - 1.
    for (size_t height{0}; height < total_height; ++height) {
        CBlock& block{*(ret.at(height) = std::make_shared<CBlock>())};

        CMutableTransaction coinbase_tx;
        coinbase_tx.nLockTime = static_cast<uint32_t>(height);
        coinbase_tx.vin.resize(1);
        coinbase_tx.vin[0].prevout.SetNull();
        coinbase_tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
        coinbase_tx.vout.resize(1);
        coinbase_tx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
        coinbase_tx.vout[0].nValue = GetBlockSubsidy(height + 1, params.GetConsensus());
        coinbase_tx.vin[0].scriptSig = CScript() << (height + 1) << OP_0;
        block.vtx = {MakeTransactionRef(std::move(coinbase_tx))};

        block.nVersion = VERSIONBITS_LAST_OLD_BLOCK_VERSION;
        block.hashPrevBlock = (height >= 1 ? *ret.at(height - 1) : params.GenesisBlock()).GetHash();
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.nTime = ++time;
        block.nBits = params.GenesisBlock().nBits;
        InitializeTensorHeader(block);
        block.nNonce = 0;
        const auto& consensus = params.GetConsensus();
        block.pow = CProofBlob();
        if (!consensus.DefaultModelName.empty() && !consensus.DefaultModelCommit.empty()) {
            block.pow.model_identifier = consensus.DefaultModelName + "@" + consensus.DefaultModelCommit;
        }

        const CBlock* prev_block = height >= 1 ? ret.at(height - 1).get() : &genesis;
        UpdateTestBlockVdf(block, prev_block, /*next_height=*/height + 1, consensus);

        while (!CheckProofOfWork(block.GetShortHash(), block.nAdjBits ? block.nAdjBits : block.nBits, params.GetConsensus())) {
            ++block.nNonce;
            assert(block.nNonce);
        }
    }
    return ret;
}

COutPoint MineBlock(const NodeContext& node, const node::BlockAssembler::Options& assembler_options)
{
    auto block = PrepareBlock(node, assembler_options);
    auto valid = MineBlock(node, block);
    assert(!valid.IsNull());
    return valid;
}

struct BlockValidationStateCatcher : public CValidationInterface {
    const uint256 m_hash;
    std::optional<BlockValidationState> m_state;

    BlockValidationStateCatcher(const uint256& hash)
        : m_hash{hash},
          m_state{} {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& state) override
    {
        if (block.GetHash() != m_hash) return;
        m_state = state;
    }
};

COutPoint MineBlock(const NodeContext& node, std::shared_ptr<CBlock>& block)
{
    while (!CheckProofOfWork(block->GetShortHash(), block->nAdjBits ? block->nAdjBits : block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }

    return ProcessBlock(node, block);
}

COutPoint ProcessBlock(const NodeContext& node, const std::shared_ptr<CBlock>& block)
{
    auto& chainman{*Assert(node.chainman)};
    const auto old_height = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight());
    bool new_block;
    BlockValidationStateCatcher bvsc{block->GetHash()};
    node.validation_signals->RegisterValidationInterface(&bvsc);
    const bool processed{chainman.ProcessNewBlock(block, true, true, &new_block)};
    const bool duplicate{!new_block && processed};
    assert(!duplicate);
    node.validation_signals->UnregisterValidationInterface(&bvsc);
    node.validation_signals->SyncWithValidationInterfaceQueue();
    const bool was_valid{bvsc.m_state && bvsc.m_state->IsValid()};
    assert(old_height + was_valid == WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight()));

    if (was_valid) return {block->vtx[0]->GetHash(), 0};
    return {};
}

std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node,
                                     const BlockAssembler::Options& assembler_options)
{
    auto block = std::make_shared<CBlock>(
        BlockAssembler{Assert(node.chainman)->ActiveChainstate(), Assert(node.mempool.get()), assembler_options}
            .CreateNewBlock()
            ->block);

    LOCK(cs_main);
    block->nTime = Assert(node.chainman)->ActiveChain().Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}
std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node, const CScript& coinbase_scriptPubKey)
{
    BlockAssembler::Options assembler_options;
    assembler_options.coinbase_output_script = coinbase_scriptPubKey;
    ApplyArgsManOptions(*node.args, assembler_options);
    return PrepareBlock(node, assembler_options);
}

// CreateTensorBlock helpers
CBlock CreateTensorBlock(NodeContext& node,
                         const std::vector<CMutableTransaction>& extra_txs,
                         const CScript& coinbase_script)
{
    using node::BlockAssembler;
    BlockAssembler::Options opts;
    opts.coinbase_output_script = coinbase_script;
    CBlock block = BlockAssembler{Assert(node.chainman)->ActiveChainstate(), Assert(node.mempool.get()), opts}
                       .CreateNewBlock()
                       ->block;

    // Append extra transactions if any
    for (const auto& tx : extra_txs) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }

    // Initialize proof-of-work blob and model identifier first
    const auto& consensus = Params().GetConsensus();
    block.pow = CProofBlob();
    if (!consensus.DefaultModelName.empty() && !consensus.DefaultModelCommit.empty()) {
        block.pow.model_identifier = consensus.DefaultModelName + "@" + consensus.DefaultModelCommit;
    }

    // Regenerate commitments and merkle root after mutating vtx and PoW blob
    node::RegenerateCommitments(block, *Assert(node.chainman));
    UpdateTestBlockVdf(block, *Assert(node.chainman));

    // Ensure adjusted bits reflect model difficulty for Tensor header
    InitializeTensorHeader(block);
    if (g_modeldb && !block.pow.model_identifier.empty()) {
        ModelRecord rec;
        const uint256 mid = block.pow.GetModelHash();
        if (g_modeldb->ReadModel(mid, rec) && rec.metadata.difficulty > 0) {
            const auto& cons = Params().GetConsensus();
            if (auto base_target = DeriveTarget(block.nBits, cons.powLimit)) {
                const uint64_t diff = static_cast<uint64_t>(rec.metadata.difficulty);
                const uint64_t norm = cons.ModelDifficultyNormalizer == 0 ? 1 : cons.ModelDifficultyNormalizer;
                arith_uint256 powlim = UintToArith256(cons.powLimit);

                arith_uint256 q = *base_target;
                arith_uint256 diff_b = arith_uint256(diff);
                q /= diff_b;
                arith_uint256 adj = q;
                if (norm != 0 && adj > (powlim / norm)) adj = powlim; else adj *= norm;
                arith_uint256 prod = q * diff_b;
                arith_uint256 rem = *base_target; rem -= prod;
                uint64_t r64 = rem.GetLow64();
                unsigned __int128 extra = 0;
                if (diff != 0) extra = (static_cast<unsigned __int128>(r64) * norm) / diff;
                if (extra > 0) { if (adj > powlim - (uint64_t)extra) adj = powlim; else adj += (uint64_t)extra; }
                block.nAdjBits = adj.GetCompact();
            }
        }
    }

    // Set cumulative tick based on previous block now that pow.tick is known
    const CBlockIndex* prev_idx{nullptr};
    {
        LOCK(cs_main);
        prev_idx = Assert(node.chainman)->ActiveChain().Tip();
    }
    if (prev_idx) {
        CBlock prev;
        if (Assert(node.chainman)->m_blockman.ReadBlock(prev, *prev_idx)) {
            block.cumulative_tick = prev.cumulative_tick + block.pow.tick;
        }
    }

    // Mine deterministically
    while (!CheckProofOfWork(block.GetShortHash(), block.nAdjBits, Params().GetConsensus())) {
        ++block.nNonce;
    }

    return block;
}

CBlock CreateTensorBlock(NodeContext& node)
{
    // Default coinbase script: OP_TRUE; no extra transactions
    return CreateTensorBlock(node, /*extra_txs=*/{}, CScript() << OP_TRUE);
}
