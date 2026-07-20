// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <assets/asset.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <validation.h>

#include <vector>
#include <map>

// Helper to create uint256 from hex string
static uint256 uint256FromHex(const std::string& hex_str) {
    // Remove "0x" prefix if present
    std::string hex = hex_str;
    if (hex.size() >= 2 && hex[0] == '0' && hex[1] == 'x') {
        hex = hex.substr(2);
    }

    // Pad to 64 characters
    if (hex.size() < 64) {
        hex = std::string(64 - hex.size(), '0') + hex;
    }

    uint256 result;
    // Fill uint256 from hex string (manually parse)
    for (size_t i = 0; i < 32 && i * 2 < hex.size(); ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        result.data()[31 - i] = std::stoul(byte_str, nullptr, 16);
    }
    return result;
}

// Benchmark TLV parsing performance
static void AssetTLVParsing(benchmark::Bench& bench)
{
    // Create various TLV samples
    std::vector<std::vector<unsigned char>> tlvs;
    
    // AssetTag TLV
    for (int i = 0; i < 100; ++i) {
        std::vector<unsigned char> tlv;
        tlv.push_back(0x01); // Type
        tlv.push_back(40);    // Length
        
        uint256 asset_id;
        asset_id.begin()[0] = i;
        tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
        
        uint64_t amount = 1000000 + i;
        unsigned char amount_bytes[8];
        WriteLE64(amount_bytes, amount);
        tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
        
        tlvs.push_back(tlv);
    }
    
    // IssuerReg TLV
    for (int i = 0; i < 100; ++i) {
        std::vector<unsigned char> tlv;
        tlv.push_back(0x10); // Type
        tlv.push_back(38);    // Length
        
        uint256 asset_id;
        asset_id.begin()[1] = i;
        tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
        
        uint32_t policy = 0x0003;
        unsigned char policy_bytes[4];
        WriteLE32(policy_bytes, policy);
        tlv.insert(tlv.end(), policy_bytes, policy_bytes + 4);
        
        uint16_t families = 0x001C;
        unsigned char family_bytes[2];
        WriteLE16(family_bytes, families);
        tlv.insert(tlv.end(), family_bytes, family_bytes + 2);
        
        tlvs.push_back(tlv);
    }
    
    size_t idx = 0;
    bench.run([&] {
        const auto& tlv = tlvs[idx % tlvs.size()];
        
        // Parse as AssetTag
        auto tag = assets::ParseAssetTag(tlv);
        
        // Parse as IssuerReg
        auto reg = assets::ParseIssuerReg(tlv);
        
        idx++;
    });
}

// Benchmark delta computation for transactions with many assets
static void AssetDeltaComputation(benchmark::Bench& bench)
{
    // Create transaction with multiple asset inputs/outputs
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    
    // Add inputs (simulated)
    for (int i = 0; i < 10; ++i) {
        CTxIn in;
        in.prevout.hash = Txid::FromUint256(uint256FromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"));
        in.prevout.n = i;
        mtx.vin.push_back(in);
    }
    
    // Add outputs with assets
    for (int i = 0; i < 20; ++i) {
        CTxOut out;
        out.nValue = 100000 * (i + 1);
        out.scriptPubKey = CScript() << OP_TRUE;
        
        // Add AssetTag
        std::vector<unsigned char> tlv;
        tlv.push_back(0x01);
        tlv.push_back(40);
        
        uint256 asset_id;
        asset_id.begin()[0] = i % 5; // 5 different assets
        tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
        
        uint64_t amount = 1000000 * (i + 1);
        unsigned char amount_bytes[8];
        WriteLE64(amount_bytes, amount);
        tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
        
        out.vExt = tlv;
        mtx.vout.push_back(out);
    }
    
    CTransaction tx(mtx);
    
    bench.run([&] {
        // Simulate delta computation
        std::map<uint256, int64_t> deltas;
        
        for (const auto& out : tx.vout) {
            if (!out.vExt.empty()) {
                auto tag = assets::ParseAssetTag(out.vExt);
                if (tag.has_value()) {
                    deltas[tag->id] += tag->amount;
                }
            }
        }
        
        // Check conservation (would check inputs in real validation)
        for (const auto& [asset_id, delta] : deltas) {
            bool valid = (delta >= 0); // Simplified check
            (void)valid;
        }
    });
}

// Benchmark registry operations at scale
static void AssetRegistryOperations(benchmark::Bench& bench)
{
    // Simulate registry with many assets
    std::map<uint256, AssetRegistryEntry> registry;
    
    // Pre-populate registry
    for (int i = 0; i < 10000; ++i) {
        uint256 asset_id;
        asset_id.begin()[0] = i & 0xFF;
        asset_id.begin()[1] = (i >> 8) & 0xFF;
        
        AssetRegistryEntry entry;
        entry.policy_bits = 0x0003;
        entry.allowed_spk_families = 0x001C;
        entry.icu_outpoint = COutPoint(Txid::FromUint256(asset_id), 0);
        entry.unlock_fees_sats = 100000000; // 1 BTC
        entry.fees_accum_sats = i * 1000;
        
        registry[asset_id] = entry;
    }
    
    size_t op_count = 0;
    bench.run([&] {
        // Perform various registry operations
        uint256 asset_id;
        asset_id.begin()[0] = op_count & 0xFF;
        asset_id.begin()[1] = (op_count >> 8) & 0xFF;
        
        // Lookup
        auto it = registry.find(asset_id);
        if (it != registry.end()) {
            // Update fees
            it->second.fees_accum_sats += 100;
            
            // Check unlock
            bool unlocked = (it->second.fees_accum_sats >= it->second.unlock_fees_sats);
            (void)unlocked;
        }
        
        op_count++;
    });
}

// Benchmark transaction serialization with vExt
static void AssetTxSerialization(benchmark::Bench& bench)
{
    // Create transactions with varying numbers of asset outputs
    std::vector<CTransaction> txs;
    
    for (int tx_idx = 0; tx_idx < 10; ++tx_idx) {
        CMutableTransaction mtx;
        mtx.version = CTransaction::CURRENT_VERSION;
        
        // Add inputs
        for (int i = 0; i < 2; ++i) {
            CTxIn in;
            in.prevout.hash = Txid::FromUint256(uint256FromHex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"));
            in.prevout.n = i;
            mtx.vin.push_back(in);
        }
        
        // Add outputs with vExt
        for (int i = 0; i < (tx_idx + 1) * 5; ++i) {
            CTxOut out;
            out.nValue = 100000 + i;
            out.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
            
            if (i % 2 == 0) {
                // Add AssetTag
                std::vector<unsigned char> tlv;
                tlv.push_back(0x01);
                tlv.push_back(40);
                
                uint256 asset_id;
                asset_id.begin()[0] = i;
                tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                
                uint64_t amount = 1000000;
                unsigned char amount_bytes[8];
                WriteLE64(amount_bytes, amount);
                tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                
                out.vExt = tlv;
            }
            
            mtx.vout.push_back(out);
        }
        
        txs.push_back(CTransaction(mtx));
    }
    
    size_t tx_idx = 0;
    bench.run([&] {
        const CTransaction& tx = txs[tx_idx % txs.size()];
        
        // Serialize
        DataStream ss;
        ss << TX_WITH_WITNESS(tx);
        
        // Deserialize
        DataStream ss2(ss);
        CMutableTransaction mtx2;
        ss2 >> TX_WITH_WITNESS(mtx2);
        
        // Compute hashes (used to prevent optimization)
        [[maybe_unused]] uint256 txid = tx.GetHash();
        [[maybe_unused]] uint256 wtxid = tx.GetWitnessHash();
        
        tx_idx++;
    });
}

// Benchmark fee accumulator distribution
static void AssetFeeDistribution(benchmark::Bench& bench)
{
    // Simulate fee distribution across many assets
    std::vector<std::set<uint256>> touched_sets;
    
    // Create various touched asset sets
    for (int i = 0; i < 100; ++i) {
        std::set<uint256> touched;
        int num_assets = (i % 20) + 1;
        
        for (int j = 0; j < num_assets; ++j) {
            uint256 asset_id;
            asset_id.begin()[0] = i;
            asset_id.begin()[1] = j;
            touched.insert(asset_id);
        }
        
        touched_sets.push_back(touched);
    }
    
    uint256 block_hash = uint256FromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    size_t idx = 0;
    
    bench.run([&] {
        const auto& touched = touched_sets[idx % touched_sets.size()];
        uint256 tx_hash;
        tx_hash.begin()[0] = idx;
        
        CAmount txfee = 100000 + (idx * 1000);
        
        if (!touched.empty()) {
            CAmount base = txfee / touched.size();
            CAmount rem = txfee % touched.size();
            
            // Calculate hash-based offset
            uint256 mix = (HashWriter{} << block_hash << tx_hash).GetHash();
            uint64_t rnd = 0;
            for (int k = 0; k < 8; ++k) {
                rnd |= (uint64_t)mix.begin()[k] << (8*k);
            }
            
            std::vector<uint256> vec(touched.begin(), touched.end());
            std::sort(vec.begin(), vec.end());
            size_t offset = (size_t)(rnd % vec.size());
            
            // Distribute (simplified)
            std::map<uint256, uint64_t> distribution;
            for (const auto& aid : vec) {
                distribution[aid] = base;
            }
            
            for (CAmount r = 0; r < rem; ++r) {
                size_t pos = (offset + (size_t)r) % vec.size();
                distribution[vec[pos]] += 1;
            }
        }
        
        idx++;
    });
}

// Benchmark mempool validation with assets
static void AssetMempoolValidation(benchmark::Bench& bench)
{
    // Create sample transactions with assets
    std::vector<CTransaction> txs;
    
    for (int i = 0; i < 100; ++i) {
        CMutableTransaction mtx;
        mtx.version = CTransaction::CURRENT_VERSION;
        
        // Add input
        CTxIn in;
        in.prevout.hash = Txid::FromUint256(uint256FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        in.prevout.n = i;
        mtx.vin.push_back(in);
        
        // Add outputs
        int num_outputs = (i % 5) + 1;
        for (int j = 0; j < num_outputs; ++j) {
            CTxOut out;
            out.nValue = 100000;
            out.scriptPubKey = CScript() << OP_TRUE;
            
            // Half have assets
            if (j % 2 == 0) {
                std::vector<unsigned char> tlv;
                tlv.push_back(0x01);
                tlv.push_back(40);
                
                uint256 asset_id;
                asset_id.begin()[0] = i % 10;
                tlv.insert(tlv.end(), asset_id.begin(), asset_id.end());
                
                uint64_t amount = 500000;
                unsigned char amount_bytes[8];
                WriteLE64(amount_bytes, amount);
                tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
                
                out.vExt = tlv;
            }
            
            mtx.vout.push_back(out);
        }
        
        txs.push_back(CTransaction(mtx));
    }
    
    size_t idx = 0;
    bench.run([&] {
        const CTransaction& tx = txs[idx % txs.size()];
        
        // Simulate basic mempool checks
        [[maybe_unused]] bool has_assets = false;
        size_t total_ext_size = 0;
        size_t asset_outputs = 0;
        
        for (const auto& out : tx.vout) {
            if (!out.vExt.empty()) {
                has_assets = true;
                total_ext_size += out.vExt.size();
                
                auto tag = assets::ParseAssetTag(out.vExt);
                if (tag.has_value()) {
                    asset_outputs++;
                }
            }
        }
        
        // Policy checks
        const size_t MAX_OUTEXT_BYTES_PER_TX = 131072;
        const size_t MAX_ASSETS_PER_TX = 64;
        
        bool valid = true;
        if (total_ext_size > MAX_OUTEXT_BYTES_PER_TX) valid = false;
        if (asset_outputs > MAX_ASSETS_PER_TX) valid = false;
        
        (void)valid;
        idx++;
    });
}

BENCHMARK(AssetTLVParsing, benchmark::PriorityLevel::HIGH);
BENCHMARK(AssetDeltaComputation, benchmark::PriorityLevel::HIGH);
BENCHMARK(AssetRegistryOperations, benchmark::PriorityLevel::HIGH);
BENCHMARK(AssetTxSerialization, benchmark::PriorityLevel::HIGH);
BENCHMARK(AssetFeeDistribution, benchmark::PriorityLevel::HIGH);
BENCHMARK(AssetMempoolValidation, benchmark::PriorityLevel::HIGH);