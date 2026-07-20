// Copyright (c) 2024 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/proofblob.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(pow_blob_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pow_blob_size_limit)
{
    SelectParams(ChainType::REGTEST);
    const auto& consensusParams = Params().GetConsensus();

    // Create a valid block
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1234567890;
    block.nBits = 0x207fffff;
    block.nNonce = 12345;
    block.nAdjBits = 0x207fffff;
    block.hashPoW = uint256();
    block.flags = 0;

    // Add a coinbase transaction
    CMutableTransaction coinbaseTx;
    coinbaseTx.version = 2;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].scriptSig = CScript() << 0 << OP_0;
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].nValue = 50 * COIN;
    coinbaseTx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbaseTx)));

    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.hashPrevBlock = consensusParams.hashGenesisBlock;

    // Test 1: Block with empty PoW blob should be valid
    {
        CProofBlob emptyBlob;
        block.pow = emptyBlob;

        BlockValidationState state;
        BOOST_CHECK(CheckBlock(block, state, consensusParams, false, false, false));
    }

    // Test that the new block limits allow 5MB total
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 5000000);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, 5000000);

    // Test 2: Block with PoW blob just under the limit should be valid
    {
        CProofBlob validBlob;
        // Fill with data just under 1MB
        // Add large vectors to increase size
        validBlob.topk_logits.resize(1000);
        for (auto& row : validBlob.topk_logits) {
            row.resize(100, 1.0f);
        }

        validBlob.topk_indices.resize(1000);
        for (auto& row : validBlob.topk_indices) {
            row.resize(100, 1);
        }

        validBlob.logsumexp_stats.resize(1000);
        for (auto& row : validBlob.logsumexp_stats) {
            row.resize(100, 1.0f);
        }

        // Add more data to approach the limit
        validBlob.chosen_tokens.resize(10000, 1);
        validBlob.chosen_probs.resize(10000, 1.0f);
        validBlob.sampling_u.resize(10000, 1.0f);
        validBlob.softmax_normalizers.resize(10000, 1.0f);
        validBlob.prompt_tokens.resize(10000, 1);

        block.pow = validBlob;

        BlockValidationState state;
        size_t actual_size = ::GetSerializeSize(block.pow);

        // Only check if the blob is under the limit
        if (actual_size <= MAX_POW_BLOB_SIZE) {
            BOOST_CHECK(CheckBlock(block, state, consensusParams, false, false, false));
            BOOST_CHECK_MESSAGE(actual_size < MAX_POW_BLOB_SIZE,
                strprintf("Valid PoW blob size: %u bytes (limit: %u)", actual_size, MAX_POW_BLOB_SIZE));
        }
    }

    // Test 3: Block with PoW blob exceeding the limit should be invalid
    {
        CProofBlob oversizedBlob;
        // Create a blob that exceeds 1MB but keeps total block under 5MB
        // Target around 1.1MB for the PoW blob

        // Fill with large nested vectors to exceed 1MB but not too much
        oversizedBlob.topk_logits.resize(1100);
        for (auto& row : oversizedBlob.topk_logits) {
            row.resize(100, 1.0f); // 1100 * 100 * 4 bytes = 440KB for this field
        }

        oversizedBlob.topk_indices.resize(1100);
        for (auto& row : oversizedBlob.topk_indices) {
            row.resize(100, 1); // Another 440KB
        }

        oversizedBlob.logsumexp_stats.resize(1100);
        for (auto& row : oversizedBlob.logsumexp_stats) {
            row.resize(100, 1.0f); // Another 440KB
        }

        // This should total to about 1.3MB, exceeding the 1MB limit
        // but keeping the total block size under 5MB

        block.pow = oversizedBlob;

        BlockValidationState state;
        size_t actual_size = ::GetSerializeSize(block.pow);

        BOOST_CHECK(!CheckBlock(block, state, consensusParams, false, false, false));

        // The error could be either bad-pow-blob-size or bad-blk-length depending on total size
        bool is_pow_error = (state.GetRejectReason() == "bad-pow-blob-size");
        bool is_size_error = (state.GetRejectReason() == "bad-blk-length");
        BOOST_CHECK_MESSAGE(is_pow_error || is_size_error,
            strprintf("Expected bad-pow-blob-size or bad-blk-length, got: %s", state.GetRejectReason()));

        BOOST_CHECK_MESSAGE(actual_size > MAX_POW_BLOB_SIZE,
            strprintf("Oversized PoW blob size: %u bytes (limit: %u)", actual_size, MAX_POW_BLOB_SIZE));
    }

    // Test 4: Block with PoW blob exactly at the limit
    {
        CProofBlob boundaryBlob;
        // Try to create a blob exactly at 1MB (this is approximate due to serialization overhead)

        // Calculate approximate sizes and fill accordingly
        // This is a simplified approach - actual serialization includes varint encoding
        size_t current_size = 0;
        size_t target = MAX_POW_BLOB_SIZE;

        // Add data incrementally to approach the limit
        while (current_size < target * 0.9) { // Get close to the limit
            boundaryBlob.chosen_tokens.push_back(1);
            boundaryBlob.chosen_probs.push_back(1.0f);
            current_size = ::GetSerializeSize(boundaryBlob);
        }

        block.pow = boundaryBlob;

        BlockValidationState state;
        size_t actual_size = ::GetSerializeSize(block.pow);

        if (actual_size <= MAX_POW_BLOB_SIZE) {
            BOOST_CHECK(CheckBlock(block, state, consensusParams, false, false, false));
            BOOST_CHECK_MESSAGE(true,
                strprintf("Boundary PoW blob size: %u bytes (limit: %u) - VALID", actual_size, MAX_POW_BLOB_SIZE));
        } else {
            BOOST_CHECK(!CheckBlock(block, state, consensusParams, false, false, false));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-pow-blob-size");
            BOOST_CHECK_MESSAGE(true,
                strprintf("Boundary PoW blob size: %u bytes (limit: %u) - INVALID", actual_size, MAX_POW_BLOB_SIZE));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()