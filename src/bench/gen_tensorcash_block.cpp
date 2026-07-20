// Generate a valid TensorCash block for benchmarking
// This program creates a minimal but valid TensorCash block with:
// - A coinbase transaction
// - One transaction with vExt (asset output)
// - Proper headers and PoW
// Copyright (c) 2024 The TensorCash developers

#include <chainparams.h>
#include <consensus/merkle.h>
#include <node/context.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <test/util/asset_utils.h>
#include <util/strencodings.h>

#include <fstream>
#include <functional>
#include <iostream>

const std::function<void(const std::string&)> G_TEST_LOG_FUN{};
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    return std::vector<const char*>{};
};
const std::function<std::string()> G_TEST_GET_FULL_NAME = []() {
    return std::string{"gen_tensorcash_block"};
};

// Helper to create an asset tag TLV
static std::vector<unsigned char> MakeAssetTag(const uint256& asset_id, uint64_t amount, uint32_t flags = 0)
{
    return test_util::BuildAssetTag(asset_id, amount, flags);
}

int main(int argc, char** argv)
{
    std::string output_file = "tensorcash_block.raw";
    if (argc > 1) {
        output_file = argv[1];
    }

    try {
        // Initialize testing environment
        BasicTestingSetup test_setup{ChainType::REGTEST};

        std::cout << "Creating TensorCash block..." << std::endl;

        // Create a simple block with coinbase
        CBlock block;
        block.nVersion = 4;
        block.hashPrevBlock.SetNull();  // Genesis-like
        block.nTime = 1231006505;
        block.nBits = 0x207fffff;  // Regtest difficulty
        block.nNonce = 0;

        // Initialize TensorCash-specific header fields
        InitializeTensorHeader(block);

        // Create coinbase transaction
        CMutableTransaction coinbase_tx;
        coinbase_tx.version = 2;
        coinbase_tx.vin.resize(1);
        coinbase_tx.vin[0].prevout.SetNull();
        coinbase_tx.vin[0].scriptSig = CScript() << 1 << OP_0;
        coinbase_tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
        coinbase_tx.vout.resize(1);
        coinbase_tx.vout[0].nValue = 50 * COIN;
        coinbase_tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

        block.vtx.push_back(MakeTransactionRef(std::move(coinbase_tx)));

        // Create a transaction with an asset output (vExt)
        CMutableTransaction asset_tx;
        asset_tx.version = 2;

        // Input: spending from coinbase (won't be validated in benchmark)
        asset_tx.vin.resize(1);
        asset_tx.vin[0].prevout = COutPoint(block.vtx[0]->GetHash(), 0);
        asset_tx.vin[0].scriptSig = CScript() << OP_TRUE;
        asset_tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;

        // Output 1: Regular output
        asset_tx.vout.emplace_back(10 * COIN, CScript() << OP_TRUE);

        // Output 2: Asset output with vExt
        uint256 asset_id;
        for (size_t i = 0; i < asset_id.size(); ++i) {
            asset_id.data()[i] = static_cast<uint8_t>(0x42 + i % 16);
        }

        CTxOut asset_out(5 * COIN, CScript() << OP_TRUE);
        asset_out.vExt = MakeAssetTag(asset_id, 1000000);  // 1M asset units
        asset_tx.vout.push_back(asset_out);

        // Output 3: Another regular output for change
        asset_tx.vout.emplace_back(34 * COIN, CScript() << OP_TRUE);

        block.vtx.push_back(MakeTransactionRef(std::move(asset_tx)));

        // Calculate merkle root
        block.hashMerkleRoot = BlockMerkleRoot(block);

        // Set up PoW blob
        const auto& consensus = Params().GetConsensus();
        block.pow = CProofBlob();
        if (!consensus.DefaultModelName.empty() && !consensus.DefaultModelCommit.empty()) {
            block.pow.model_identifier = consensus.DefaultModelName + "@" + consensus.DefaultModelCommit;
        }

        // Set VDF fields for TensorCash (using offline variant since no chain)
        UpdateTestBlockVdf(block, /*prev_cumulative_tick=*/uint64_t{0}, /*next_height=*/1, consensus);

        // Mine the block (find valid nonce)
        std::cout << "Mining block..." << std::endl;
        while (!CheckProofOfWork(block.GetShortHash(),
                                 block.nAdjBits ? block.nAdjBits : block.nBits,
                                 consensus)) {
            ++block.nNonce;
            if (block.nNonce % 10000 == 0) {
                std::cout << "  Nonce: " << block.nNonce << "\r" << std::flush;
            }
        }
        std::cout << "\nBlock mined with nonce: " << block.nNonce << std::endl;

        // Serialize block to file
        std::cout << "Serializing block to " << output_file << "..." << std::endl;

        DataStream ss{};
        ss << TX_WITH_WITNESS(block);

        std::ofstream file(output_file, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file for writing: " << output_file << std::endl;
            return 1;
        }

        file.write(reinterpret_cast<const char*>(ss.data()), ss.size());
        file.close();

        std::cout << "Block saved successfully!" << std::endl;
        std::cout << "Block hash: " << block.GetHash().ToString() << std::endl;
        std::cout << "Block size: " << ss.size() << " bytes" << std::endl;
        std::cout << "Transactions: " << block.vtx.size() << std::endl;
        std::cout << "  - Coinbase: " << block.vtx[0]->GetHash().ToString() << std::endl;
        std::cout << "  - Asset tx: " << block.vtx[1]->GetHash().ToString() << std::endl;
        std::cout << "    with vExt size: " << block.vtx[1]->vout[1].vExt.size() << " bytes" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
