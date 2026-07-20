// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <streams.h>
#include <signet.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <assets/asset.h>
#include <script/signingprovider.h>
#include <addresstype.h>
#include <pow.h>
#include <modeldb.h>
#include <test/util/transaction_utils.h>
#include <test/util/asset_utils.h>
#include <assets/registry.h>
#include <kernel/disconnected_transactions.h>

#include <test/util/setup_common.h>

#include <limits>
#include <string>

#include <boost/test/unit_test.hpp>

extern bool TestOnly_IsModelDepositSpendAllowed(const ModelRecord& record, int spend_height, const Consensus::Params& params);
extern int TestOnly_GetModelBurnAllowedHeight(const ModelRecord& record, const Consensus::Params& params);

BOOST_AUTO_TEST_SUITE(validation_tests)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_FIXTURE_TEST_CASE(block_subsidy_test, BasicTestingSetup)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval

    // TensorCash: basic sanity checks for Tensor mainnet subsidy schedule.
    const auto tensorParams = CreateChainParams(*m_node.args, ChainType::TENSOR_MAIN);
    const auto& tensorConsensus = tensorParams->GetConsensus();
    BOOST_CHECK(tensorConsensus.tensor_subsidy);

    const CAmount initial = GetBlockSubsidy(0, tensorConsensus);
    BOOST_CHECK_EQUAL(initial, CAmount{715} * COIN);

    // First epoch: constant reward for [0, 715).
    BOOST_CHECK_EQUAL(GetBlockSubsidy(714, tensorConsensus), initial);

    const CAmount epoch1_reward = GetBlockSubsidy(715, tensorConsensus);
    BOOST_CHECK_EQUAL(epoch1_reward, (initial * 3) / 5);
    // Epoch 1 spans [715, 715 + 1430).
    BOOST_CHECK_EQUAL(GetBlockSubsidy(715 + 1430 - 1, tensorConsensus), epoch1_reward);

    const CAmount epoch2_reward = GetBlockSubsidy(715 + 1430, tensorConsensus);
    BOOST_CHECK_EQUAL(epoch2_reward, (epoch1_reward * 3) / 5);
}

BOOST_FIXTURE_TEST_CASE(subsidy_limit_test, BasicTestingSetup)
{
    // Bitcoin mainnet: classic halving schedule remains unchanged.
    {
        const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
        CAmount nSum = 0;
        for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
            CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
            BOOST_CHECK(nSubsidy <= 50 * COIN);
            nSum += nSubsidy * 1000;
            BOOST_CHECK(MoneyRange(nSum));
        }
        BOOST_CHECK_EQUAL(nSum, CAmount{2099999997690000});
    }

    // Tensor mainnet: epoch-based schedule with asymptotic total supply.
    {
        const auto tensorParams = CreateChainParams(*m_node.args, ChainType::TENSOR_MAIN);
        const auto& consensus = tensorParams->GetConsensus();
        BOOST_CHECK(consensus.tensor_subsidy);

        static constexpr CAmount kInitialReward{715 * COIN};
        static constexpr int kEpochStartLen{715};
        static constexpr int kEpochCapLen{kEpochStartLen * (1 << 10)};
        static constexpr int kP{3};
        static constexpr int kQ{5};

        CAmount reward = kInitialReward;
        int epoch_len = kEpochStartLen;
        int height = 0;
        CAmount total{0};

        // Precomputed total subsidy from this recurrence (in satoshis).
        static constexpr CAmount EXPECTED_TOTAL{CAmount{2118415303530240}};

        while (reward > 0) {
            const CAmount epoch_minted = reward * epoch_len;
            total += epoch_minted;

            const int start = height;
            const int end = height + epoch_len;

            // Sanity-check GetBlockSubsidy is constant inside the epoch.
            BOOST_CHECK_EQUAL(GetBlockSubsidy(start, consensus), reward);
            BOOST_CHECK_EQUAL(GetBlockSubsidy(end - 1, consensus), reward);

            height = end;
            reward = (reward * kP) / kQ;
            epoch_len = std::min(epoch_len * 2, kEpochCapLen);
        }

        // After the final decay step, subsidy must be zero.
        BOOST_CHECK_EQUAL(GetBlockSubsidy(height, consensus), 0);

        BOOST_CHECK_EQUAL(total, EXPECTED_TOTAL);

        // Convergence sanity: extending with additional zero-subsidy epochs
        // does not change the total.
        CAmount extended_total = total;
        for (int i = 0; i < 4; ++i) {
            extended_total += GetBlockSubsidy(height + i * kEpochCapLen, consensus) * kEpochCapLen;
        }
        BOOST_CHECK_EQUAL(extended_total, EXPECTED_TOTAL);
    }
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

BOOST_FIXTURE_TEST_CASE(model_deposit_spend_rules, BasicTestingSetup)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& consensus = chain_params->GetConsensus();

    ModelRecord record;
    record.deposit_block_height = 100;

    record.status = ModelRegistrationStatus::PendingDeposit;
    BOOST_CHECK(!TestOnly_IsModelDepositSpendAllowed(record, record.deposit_block_height, consensus));

    record.status = ModelRegistrationStatus::PendingVerification;
    BOOST_CHECK(!TestOnly_IsModelDepositSpendAllowed(record, record.deposit_block_height + consensus.ModelCommitRefundDelay, consensus));

    record.status = ModelRegistrationStatus::Locked;
    BOOST_CHECK(!TestOnly_IsModelDepositSpendAllowed(record, record.deposit_block_height + consensus.ModelCommitRefundDelay + 5, consensus));

    record.status = ModelRegistrationStatus::Banned;
    BOOST_CHECK(!TestOnly_IsModelDepositSpendAllowed(record, record.deposit_block_height + consensus.ModelCommitRefundDelay + 5, consensus));

    record.status = ModelRegistrationStatus::Registered;
    int spend_height = record.deposit_block_height + consensus.ModelCommitRefundDelay;
    BOOST_CHECK(!TestOnly_IsModelDepositSpendAllowed(record, spend_height - 1, consensus));
    BOOST_CHECK(TestOnly_IsModelDepositSpendAllowed(record, spend_height, consensus));

    record.deposit_block_height = 0;
    BOOST_CHECK(!TestOnly_IsModelDepositSpendAllowed(record, spend_height, consensus));
}

BOOST_FIXTURE_TEST_CASE(model_burn_height_rules, BasicTestingSetup)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& consensus = chain_params->GetConsensus();

    ModelRecord record;

    record.status = ModelRegistrationStatus::Locked;
    record.commit_block_height = 250;
    BOOST_CHECK_EQUAL(TestOnly_GetModelBurnAllowedHeight(record, consensus), 250);

    record.status = ModelRegistrationStatus::Banned;
    record.burn_block_height = 320;
    BOOST_CHECK_EQUAL(TestOnly_GetModelBurnAllowedHeight(record, consensus), 320);

    record.status = ModelRegistrationStatus::Registered;
    record.commit_block_height = 400;
    int expected_unlock = record.commit_block_height + consensus.ModelCommitRefundDelay;
    BOOST_CHECK_EQUAL(TestOnly_GetModelBurnAllowedHeight(record, consensus), expected_unlock);

    record.status = ModelRegistrationStatus::PendingDeposit;
    record.commit_block_height = 0;
    BOOST_CHECK_EQUAL(TestOnly_GetModelBurnAllowedHeight(record, consensus), std::numeric_limits<int>::max());

    record.status = ModelRegistrationStatus::PendingVerification;
    record.commit_block_height = 600;
    BOOST_CHECK_EQUAL(TestOnly_GetModelBurnAllowedHeight(record, consensus), 600 + consensus.ModelCommitRefundDelay);
}

//! Test retrieval of valid assumeutxo values.
BOOST_FIXTURE_TEST_CASE(test_assumeutxo, BasicTestingSetup)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    // We have data for heights 100, 110, 200, 299 with VDF enabled (TestChain100Setup values)
    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto out110_2 = *params->AssumeutxoForBlockhash(uint256{"c1749202db9c5bad7d32a863077e6211a0f8f2b37bf686e493a2a70b0dde14ff"});
    BOOST_CHECK_EQUAL(out110_2.hash_serialized.ToString(), "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327");
    BOOST_CHECK_EQUAL(out110_2.m_chain_tx_count, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

// Asset-related validation tests
BOOST_FIXTURE_TEST_CASE(connect_block_with_asset_registry, TestChain100Setup)
{
    // Test that ConnectBlock properly writes asset registry entries
    auto& chainstate = m_node.chainman->ActiveChainstate();
    
    // Create a block with an IssuerReg transaction
    CBlock block;
    block.nVersion = 1;
    block.nTime = chainstate.m_chain.Tip()->GetBlockTime() + 1;
    block.hashPrevBlock = chainstate.m_chain.Tip()->GetBlockHash();
    // Keep header fields coherent for just-check connect
    block.nBits = chainstate.m_chain.Tip()->nBits;
    block.nAdjBits = block.nBits;
    // Ensure Tensor header fields are initialized to avoid incidental header checks tripping
    block.nBits = chainstate.m_chain.Tip()->nBits;
    block.nAdjBits = block.nBits;
    
    // Create coinbase
    CMutableTransaction coinbase;
    coinbase.version = 1;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << chainstate.m_chain.Height() + 1;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = GetBlockSubsidy(chainstate.m_chain.Height() + 1, Params().GetConsensus());
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    
    // Build outputs with IssuerReg TLV first, then sign the transaction so signatures commit to vExt
    uint256 asset_id;
    memset(asset_id.data(), 0x01, asset_id.size());
    std::vector<unsigned char> issuer_reg_tlv = test_util::BuildV1IssuerReg(asset_id, 0, 0xFFFF);
    CTxOut out{(5 * COIN), CScript() << OP_TRUE};
    out.vExt = issuer_reg_tlv;
    COutPoint input{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction issuer_tx = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{input},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{out},
        /*submit=*/false);
    
    block.vtx.push_back(MakeTransactionRef(std::move(issuer_tx)));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Mine PoW for regtest
    while (!CheckProofOfWork(block.GetShortHash(), block.nAdjBits ? block.nAdjBits : block.nBits, Params().GetConsensus())) {
        ++block.nNonce;
    }

    // Connect the block using a dummy index for this new block (as upstream does)
    CCoinsViewCache view(&chainstate.CoinsTip());
    BlockValidationState state;
    uint256 blk_hash = block.GetHash();  // Compute hash AFTER mining
    CBlockIndex indexDummy(block);
    indexDummy.pprev = chainstate.m_chain.Tip();
    indexDummy.nHeight = chainstate.m_chain.Tip()->nHeight + 1;
    indexDummy.phashBlock = &blk_hash;
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(
            chainstate.ConnectBlock(block, state, &indexDummy, view, /*fJustCheck=*/false),
            strprintf("ConnectBlock failed: %s", state.ToString())
        );
        // Flush the view to commit registry writes to database
        view.Flush();
    }

    // Verify registry entry was created
    AssetRegistryEntry entry;
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(asset_id, entry));
    BOOST_CHECK_EQUAL(entry.allowed_spk_families, 0xFFFF);
    BOOST_CHECK(entry.icu_outpoint == COutPoint(block.vtx[1]->GetHash(), 0));
}

// Integration: accept issuer registration via ProcessNewBlock
BOOST_FIXTURE_TEST_CASE(connect_block_with_asset_registry_pnb, TestChain100Setup)
{
    auto& chainstate = m_node.chainman->ActiveChainstate();

    // Build outputs with IssuerReg TLV first, then sign so vExt is committed
    uint256 asset_id; memset(asset_id.data(), 0x01, asset_id.size());
    std::vector<unsigned char> tlv = test_util::BuildV1IssuerReg(asset_id, 0, 0xFFFF);
    CTxOut out{(5 * COIN), CScript() << OP_TRUE};
    out.vExt = tlv;
    COutPoint inpt{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction issuer_tx = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{inpt},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{out},
        /*submit=*/false);

    CBlock block = CreateAndProcessBlock({issuer_tx}, CScript() << OP_TRUE);

    AssetRegistryEntry entry;
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(asset_id, entry));
    BOOST_CHECK_EQUAL(entry.allowed_spk_families, 0xFFFF);
    BOOST_CHECK(entry.icu_outpoint == COutPoint(block.vtx[1]->GetHash(), 0));
}

BOOST_FIXTURE_TEST_CASE(disconnect_block_with_asset_registry, TestChain100Setup)
{
    // Test that disconnecting the tip reverts asset registry entries
    auto& chainstate = m_node.chainman->ActiveChainstate();

    // Build and accept a block with an issuer registration
    uint256 asset_id; memset(asset_id.data(), 0x02, asset_id.size());
    // Build outputs with IssuerReg TLV first, then sign so vExt is committed
    CTxOut rout{(5 * COIN), CScript() << OP_TRUE};
    std::vector<unsigned char> tlv = test_util::BuildV1IssuerReg(asset_id, 0x01, 0x05);
    rout.vExt = tlv;
    COutPoint rin{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction tx = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{rin},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{rout},
        /*submit=*/false);
    CBlock block = CreateAndProcessBlock({tx}, CScript() << OP_TRUE);

    AssetRegistryEntry entry;
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(asset_id, entry));

    // Safely reorg away from the tip by invalidating the last block
    CBlockIndex* pidx_tip = nullptr;
    {
        LOCK(cs_main);
        pidx_tip = m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE(pidx_tip != nullptr);
    }
    BlockValidationState s;
    BOOST_CHECK(chainstate.InvalidateBlock(s, pidx_tip));
    BOOST_CHECK(!chainstate.CoinsTip().ReadAssetPolicy(asset_id, entry));
}

BOOST_FIXTURE_TEST_CASE(reorg_with_asset_registry, TestChain100Setup)
{
    // Test registry behavior across a reorg by disconnecting and replacing tip
    auto& chainstate = m_node.chainman->ActiveChainstate();

    uint256 asset1; memset(asset1.data(), 0x11, asset1.size());
    uint256 asset2; memset(asset2.data(), 0x22, asset2.size());

    // Accept block A with asset1 registration
    // Block A: build outputs with IssuerReg TLV first, then sign so vExt is committed
    CTxOut outA{(5 * COIN), CScript() << OP_TRUE};
    std::vector<unsigned char> tlvA = test_util::BuildV1IssuerReg(asset1, 0, 0);
    outA.vExt = tlvA;
    COutPoint inA{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction txA = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{inA},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{outA},
        /*submit=*/false);
    CBlock blockA = CreateAndProcessBlock({txA}, CScript() << OP_TRUE);
    AssetRegistryEntry entry;
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(asset1, entry));
    BOOST_CHECK(!chainstate.CoinsTip().ReadAssetPolicy(asset2, entry));

    // Safely reorg away from A by invalidating it
    CBlockIndex* pidxA_tip = nullptr;
    {
        LOCK(cs_main);
        pidxA_tip = m_node.chainman->m_blockman.LookupBlockIndex(blockA.GetHash());
        BOOST_REQUIRE(pidxA_tip != nullptr);
    }
    BlockValidationState s;
    BOOST_CHECK(chainstate.InvalidateBlock(s, pidxA_tip));

    // Accept block B with asset2 registration
    CTxOut outB{(5 * COIN), CScript() << OP_TRUE};
    std::vector<unsigned char> tlvB = test_util::BuildV1IssuerReg(asset2, 0, 0);
    outB.vExt = tlvB;
    COutPoint inB{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction txB = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{inB},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{outB},
        /*submit=*/false);
    CBlock blockB = CreateAndProcessBlock({txB}, CScript() << OP_TRUE);

    BOOST_CHECK(!chainstate.CoinsTip().ReadAssetPolicy(asset1, entry));
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(asset2, entry));
}

// Phase B / 5c parity test: a reorg round-trip (invalidate then reconsider) must
// restore the asset registry's policy + ticker entries bit-for-bit. Two assets are
// registered in two stacked blocks; invalidating the lower block disconnects both
// registrations (DisconnectBlock reverts the staged registry through the same view as
// the coins undo), and reconsidering re-stages them through ConnectBlock + the atomic
// BatchWrite commit. The serialized AssetRegistryEntry + ticker binding must be
// byte-identical before and after — proving the registry travels with the coins view
// across disconnect/reconnect, not on its own independently-committed cadence. (Parity is
// checked for the policy 'R' and ticker 'T' families an IssuerReg populates; ICU-payload
// and zk-VK families need an ICU payload / zk proof and are not exercised by this fixture.)
BOOST_FIXTURE_TEST_CASE(asset_registry_invalidate_reconsider_parity, TestChain100Setup)
{
    auto& chainstate = m_node.chainman->ActiveChainstate();

    uint256 assetX; memset(assetX.data(), 0x33, assetX.size());
    uint256 assetY; memset(assetY.data(), 0x44, assetY.size());

    // Block A registers assetX/"REORGX" (spends mature coinbase 0).
    CTxOut outX{(5 * COIN), CScript() << OP_TRUE};
    outX.vExt = test_util::BuildV1IssuerReg(assetX, 0x01, 0x07, "REORGX");
    CMutableTransaction txX = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{outX},
        /*submit=*/false);
    CBlock blockA = CreateAndProcessBlock({txX}, CScript() << OP_TRUE);

    // Block B (on A) registers assetY/"REORGY" (spends mature coinbase 1).
    CTxOut outY{(5 * COIN), CScript() << OP_TRUE};
    outY.vExt = test_util::BuildV1IssuerReg(assetY, 0x02, 0x0F, "REORGY");
    CMutableTransaction txY = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(1)},
        /*inputs=*/{COutPoint(m_coinbase_txns.at(1)->GetHash(), 0)},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{outY},
        /*submit=*/false);
    CBlock blockB = CreateAndProcessBlock({txY}, CScript() << OP_TRUE);

    // Serialize an asset's policy entry + ticker binding to bytes, or nullopt if absent.
    auto dump = [&](const uint256& aid, const std::string& ticker) -> std::optional<std::vector<std::byte>> {
        AssetRegistryEntry e;
        if (!chainstate.CoinsTip().ReadAssetPolicy(aid, e)) return std::nullopt;
        DataStream ss;
        ss << e;
        uint256 bound;
        const bool has_ticker = !ticker.empty() && chainstate.CoinsTip().ReadTickerBinding(ticker, bound);
        ss << static_cast<uint8_t>(has_ticker ? 1 : 0);
        if (has_ticker) ss << bound;
        return std::vector<std::byte>(ss.begin(), ss.end());
    };

    const auto baselineX = dump(assetX, "REORGX");
    const auto baselineY = dump(assetY, "REORGY");
    BOOST_REQUIRE(baselineX.has_value());
    BOOST_REQUIRE(baselineY.has_value());

    CBlockIndex* pidxA = nullptr;
    {
        LOCK(cs_main);
        pidxA = m_node.chainman->m_blockman.LookupBlockIndex(blockA.GetHash());
        BOOST_REQUIRE(pidxA != nullptr);
    }

    // Invalidate block A: disconnects B then A. Both registrations must be gone.
    {
        BlockValidationState s;
        BOOST_CHECK(chainstate.InvalidateBlock(s, pidxA));
    }
    BOOST_CHECK(!dump(assetX, "REORGX").has_value());
    BOOST_CHECK(!dump(assetY, "REORGY").has_value());

    // Reconsider block A: clear the failure flags and re-activate. ConnectBlock
    // re-stages both registrations in original order (A then B).
    {
        LOCK(cs_main);
        chainstate.ResetBlockFailureFlags(pidxA);
    }
    {
        BlockValidationState s;
        BOOST_CHECK(chainstate.ActivateBestChain(s, nullptr));
    }

    // The chain is back at block B...
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), blockB.GetHash());
    }
    // ...and both registry entries (policy + ticker) are byte-identical to the baseline.
    const auto restoredX = dump(assetX, "REORGX");
    const auto restoredY = dump(assetY, "REORGY");
    BOOST_REQUIRE(restoredX.has_value());
    BOOST_REQUIRE(restoredY.has_value());
    BOOST_CHECK(restoredX == baselineX);
    BOOST_CHECK(restoredY == baselineY);
}

BOOST_FIXTURE_TEST_CASE(coinbase_asset_restriction, TestChain100Setup)
{
    // Test that coinbase outputs cannot contain asset tags
    auto& chainstate = m_node.chainman->ActiveChainstate();
    
    CBlock block;
    block.nVersion = 1;
    block.nTime = chainstate.m_chain.Tip()->GetBlockTime() + 1;
    block.hashPrevBlock = chainstate.m_chain.Tip()->GetBlockHash();
    
    // Create coinbase with asset tag (invalid)
    CMutableTransaction coinbase;
    coinbase.version = CTransaction::CURRENT_VERSION;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << chainstate.m_chain.Height() + 1;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = GetBlockSubsidy(chainstate.m_chain.Height() + 1, Params().GetConsensus());
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    
    // Add invalid AssetTag to coinbase output
    uint256 asset_id;
    memset(asset_id.data(), 0xAA, asset_id.size());
    std::vector<unsigned char> asset_tag_tlv;
    asset_tag_tlv.push_back(0x01); // AssetTag type
    asset_tag_tlv.push_back(44);   // Length: 32 + 8 + 4
    asset_tag_tlv.insert(asset_tag_tlv.end(), asset_id.begin(), asset_id.end());
    // Amount (8 bytes LE)
    for (int i = 0; i < 8; i++) asset_tag_tlv.push_back(0x00);
    asset_tag_tlv[32] = 0x64; // 100
    // Flags (4 bytes LE)
    for (int i = 0; i < 4; i++) asset_tag_tlv.push_back(0x00);
    coinbase.vout[0].vExt = asset_tag_tlv;
    
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    
    // Connect should fail due to coinbase asset restriction; use dummy index
    CCoinsViewCache view(&chainstate.CoinsTip());
    BlockValidationState state;
    uint256 hashC = block.GetHash();
    CBlockIndex idxC(block);
    idxC.pprev = chainstate.m_chain.Tip();
    idxC.nHeight = chainstate.m_chain.Tip()->nHeight + 1;
    idxC.phashBlock = &hashC;
    {
        LOCK(cs_main);
        BOOST_CHECK(!chainstate.ConnectBlock(block, state, &idxC, view, /*fJustCheck=*/true));
    }
    BOOST_CHECK(state.GetRejectReason().find("coinbase") != std::string::npos ||
                state.GetRejectReason().find("asset") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(coinbase_unknown_tlv_forbidden, TestChain100Setup)
{
    // Test that coinbase outputs with unknown TLV are consensus-invalid
    auto& chainstate = m_node.chainman->ActiveChainstate();

    CBlock block;
    block.nVersion = 1;
    block.nTime = chainstate.m_chain.Tip()->GetBlockTime() + 1;
    block.hashPrevBlock = chainstate.m_chain.Tip()->GetBlockHash();

    // Create coinbase
    CMutableTransaction coinbase;
    coinbase.version = CTransaction::CURRENT_VERSION;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << chainstate.m_chain.Height() + 1;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = GetBlockSubsidy(chainstate.m_chain.Height() + 1, Params().GetConsensus());
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Add unknown TLV to coinbase output (type 0x99)
    std::vector<unsigned char> tlv;
    tlv.push_back(0x99);
    tlv.push_back(0x01);
    tlv.push_back(0xAA);
    coinbase.vout[0].vExt = std::move(tlv);

    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    CCoinsViewCache view(&chainstate.CoinsTip());
    BlockValidationState state;
    uint256 h = block.GetHash();
    CBlockIndex idx(block);
    idx.pprev = chainstate.m_chain.Tip();
    idx.nHeight = chainstate.m_chain.Tip()->nHeight + 1;
    idx.phashBlock = &h;
    BOOST_CHECK(!chainstate.ConnectBlock(block, state, &idx, view, /*fJustCheck=*/true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "outext");
}

BOOST_FIXTURE_TEST_CASE(duplicate_registration_forbidden, TestChain100Setup)
{
    // Block A registers an asset via its coinbase; block B (built on A, sharing one
    // view) attempts to re-register the same asset without spending the current ICU,
    // which must be rejected. After slice-5 staging, block A's registration lives in
    // the shared view's overlay and is visible to block B (as ConnectTip threads one
    // view through the block it connects).
    auto& chainstate = m_node.chainman->ActiveChainstate();
    LOCK(cs_main);

    uint256 asset_id; memset(asset_id.data(), 0x55, asset_id.size());
    CCoinsViewCache view(&chainstate.CoinsTip());

    auto build_coinbase_reg_block = [&](const CBlockIndex* prev, int height) {
        CBlock block;
        block.nVersion = 1;
        block.nTime = prev->GetBlockTime() + 1;
        block.hashPrevBlock = prev->GetBlockHash();
        block.nBits = prev->nBits;
        block.nAdjBits = block.nBits;

        CMutableTransaction coinbase;
        coinbase.version = CTransaction::CURRENT_VERSION;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << height;
        coinbase.vout.resize(1);
        coinbase.vout[0].nValue = GetBlockSubsidy(height, Params().GetConsensus());
        coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
        coinbase.vout[0].vExt = test_util::BuildV1IssuerReg(asset_id, 0, assets::SPK_P2WPKH);

        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        block.hashMerkleRoot = BlockMerkleRoot(block);
        while (!CheckProofOfWork(block.GetShortHash(), block.nAdjBits ? block.nAdjBits : block.nBits, Params().GetConsensus())) {
            ++block.nNonce;
        }
        return block;
    };

    // Block A: build on the current tip and connect (stages the registration into `view`).
    const int heightA = chainstate.m_chain.Tip()->nHeight + 1;
    CBlock blockA = build_coinbase_reg_block(chainstate.m_chain.Tip(), heightA);
    uint256 hA = blockA.GetHash();
    CBlockIndex idxA(blockA);
    idxA.pprev = chainstate.m_chain.Tip();
    idxA.nHeight = heightA;
    idxA.phashBlock = &hA;
    {
        BlockValidationState state;
        BOOST_CHECK(chainstate.ConnectBlock(blockA, state, &idxA, view));
    }

    // Block B: build on block A, re-registering the same asset without spending the
    // ICU -> must be rejected. Block B reads the registration from the shared view.
    CBlock blockB = build_coinbase_reg_block(&idxA, heightA + 1);
    uint256 hB = blockB.GetHash();
    CBlockIndex idxB(blockB);
    idxB.pprev = &idxA;
    idxB.nHeight = heightA + 1;
    idxB.phashBlock = &hB;
    {
        BlockValidationState state;
        BOOST_CHECK(!chainstate.ConnectBlock(blockB, state, &idxB, view));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "asset-duplicate-registration");
    }
}

// Regression for the post-spend ICU-lookup fix: spending an asset's current ICU
// without providing a new IssuerReg (no rotation), while the asset is still locked,
// must be rejected with asset-bond-rotation. Before the fix, icu_spent was computed
// from already-spent coins (always empty), so this enforcement never fired.
BOOST_FIXTURE_TEST_CASE(icu_spend_without_rotation_forbidden, TestChain100Setup)
{
    auto& chainstate = m_node.chainman->ActiveChainstate();
    uint256 asset_id; memset(asset_id.data(), 0x77, asset_id.size());

    // Block A: register the asset via a tx (locked: default unlock_fees = MAX). Its
    // vout[0] becomes the ICU. CreateAndProcessBlock connects it to the chain.
    CTxOut reg_out{5 * COIN, CScript() << OP_DROP << OP_TRUE};  // OP_DROP consumes the spending sig
    reg_out.vExt = test_util::BuildV1IssuerReg(asset_id, 0, assets::SPK_P2WPKH);
    CMutableTransaction issuer_tx = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{COutPoint(m_coinbase_txns.at(0)->GetHash(), 0)},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{reg_out},
        /*submit=*/false);
    CBlock blockA = CreateAndProcessBlock({issuer_tx}, CScript() << OP_TRUE);
    const COutPoint icu_outpoint(blockA.vtx[1]->GetHash(), 0);
    {
        LOCK(cs_main);
        AssetRegistryEntry e;
        BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(asset_id, e));
        BOOST_CHECK(e.icu_outpoint == icu_outpoint);
    }

    // Block B (on A): spend the ICU with no new IssuerReg -> asset-bond-rotation.
    LOCK(cs_main);
    CBlockIndex* tip = chainstate.m_chain.Tip();
    const int heightB = tip->nHeight + 1;

    CMutableTransaction coinbase;
    coinbase.version = CTransaction::CURRENT_VERSION;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << heightB;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = GetBlockSubsidy(heightB, Params().GetConsensus());
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CMutableTransaction spend_tx;
    spend_tx.version = CTransaction::CURRENT_VERSION;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout = icu_outpoint;       // spend the ICU
    // Push a DER signature (SIGHASH_ALL) in the scriptSig so the ICU spend passes the
    // ICU authorization check (icu-missing-signature) and reaches the bond-rotation
    // enforcement. The OP_DROP in the ICU output consumes it, so the spend is also
    // script-valid (no witness on a non-witness output). Zero asset delta here, so the
    // stricter output-binding sighash rule does not apply.
    const std::vector<unsigned char> der_sig{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, SIGHASH_ALL};
    spend_tx.vin[0].scriptSig = CScript() << der_sig;
    spend_tx.vout.resize(1);
    spend_tx.vout[0].nValue = 4 * COIN;           // no IssuerReg attached -> no rotation
    spend_tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CBlock blockB;
    blockB.nVersion = 1;
    blockB.nTime = tip->GetBlockTime() + 1;
    blockB.hashPrevBlock = tip->GetBlockHash();
    blockB.nBits = tip->nBits;
    blockB.nAdjBits = blockB.nBits;
    blockB.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    blockB.vtx.push_back(MakeTransactionRef(std::move(spend_tx)));
    blockB.hashMerkleRoot = BlockMerkleRoot(blockB);
    while (!CheckProofOfWork(blockB.GetShortHash(), blockB.nAdjBits ? blockB.nAdjBits : blockB.nBits, Params().GetConsensus())) {
        ++blockB.nNonce;
    }

    CCoinsViewCache view(&chainstate.CoinsTip());
    BlockValidationState state;
    uint256 hB = blockB.GetHash();
    CBlockIndex idxB(blockB);
    idxB.pprev = tip;
    idxB.nHeight = heightB;
    idxB.phashBlock = &hB;
    BOOST_CHECK(!chainstate.ConnectBlock(blockB, state, &idxB, view));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "asset-bond-rotation");

    // Validation-only (fJustCheck) connection must reach the same verdict: asset state
    // (policy/VK/ICU) is staged into the disposable view so the enforcement sees it,
    // exactly as in real block connection. This guards against fJustCheck divergence.
    CCoinsViewCache view_jc(&chainstate.CoinsTip());
    BlockValidationState state_jc;
    BOOST_CHECK(!chainstate.ConnectBlock(blockB, state_jc, &idxB, view_jc, /*fJustCheck=*/true));
    BOOST_CHECK_EQUAL(state_jc.GetRejectReason(), "asset-bond-rotation");
}

BOOST_FIXTURE_TEST_CASE(icu_sighash_anyonecanpay_forbidden, TestChain100Setup)
{
    // Build a chain, register an asset with a P2WPKH ICU, then attempt a mint
    // where the ICU input is signed with ANYONECANPAY. ConnectBlock must reject.
    auto& chainstate = m_node.chainman->ActiveChainstate();

    // Accept a real block containing the registration tx that spends last coinbase

    // Prepare key and P2WPKH script for ICU
    FillableSigningProvider keystore;
    CKey icu_key; icu_key.MakeNewKey(true);
    BOOST_CHECK(keystore.AddKey(icu_key));
    CPubKey icu_pub = icu_key.GetPubKey();
    WitnessV0KeyHash wpkh(icu_pub.GetID());
    CScript icu_spk = GetScriptForDestination(wpkh);

    // Registration tx (spends a matured coinbase from height 1). Build outputs with vExt first, then sign.
    uint256 aid; memset(aid.data(), 0x77, aid.size());
    uint32_t pol = assets::MINT_ALLOWED | assets::BURN_ALLOWED;
    auto regtlv = test_util::BuildV1IssuerReg(aid, pol, assets::SPK_DEFAULT_ALLOWED);
    CTxOut outReg(5 * COIN, icu_spk);  // Use minimum bond amount (5 BTC)
    outReg.vExt = regtlv;
    COutPoint coinbasePrev{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction reg = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{coinbasePrev},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{outReg},
        /*submit=*/false);
    CBlock blockA = CreateAndProcessBlock({reg}, CScript() << OP_TRUE);
    // Ensure registry reflects the new ICU and capture its outpoint
    AssetRegistryEntry reg_entry;
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(aid, reg_entry));

    // Now build a block with a mint tx spending the ICU with ANYONECANPAY signature
    CBlock blockB;
    blockB.nVersion = 1;
    blockB.nTime = chainstate.m_chain.Tip()->GetBlockTime() + 1;
    blockB.hashPrevBlock = chainstate.m_chain.Tip()->GetBlockHash();
    blockB.nBits = chainstate.m_chain.Tip()->nBits;
    blockB.nAdjBits = blockB.nBits;

    // Coinbase B
    CMutableTransaction cbB;
    cbB.version = CTransaction::CURRENT_VERSION;
    cbB.vin.resize(1);
    cbB.vin[0].prevout.SetNull();
    cbB.vin[0].scriptSig = CScript() << chainstate.m_chain.Height() + 1;
    cbB.vout.resize(1);
    cbB.vout[0].nValue = GetBlockSubsidy(chainstate.m_chain.Height() + 1, Params().GetConsensus());
    cbB.vout[0].scriptPubKey = CScript() << OP_TRUE;
    blockB.vtx.push_back(MakeTransactionRef(std::move(cbB)));

    // Mint tx
    CMutableTransaction mint;
    mint.version = CTransaction::CURRENT_VERSION;
    mint.vin.resize(2);
    // Use ICU outpoint recorded in registry
    mint.vin[0].prevout = reg_entry.icu_outpoint;
    // Add another input to cover the asset output value and fee
    mint.vin[1].prevout = COutPoint{m_coinbase_txns.at(1)->GetHash(), 0};
    // vout0: rotate ICU to same key, same value
    mint.vout.emplace_back(5 * COIN, icu_spk);  // Maintain the same ICU value
    // attach IssuerReg again
    mint.vout[0].vExt = regtlv;
    // vout1: AssetTag mint
    CTxOut asset_out(1000, GetScriptForDestination(wpkh));
    {
        std::vector<unsigned char> tagp; tagp.insert(tagp.end(), aid.begin(), aid.end()); uint64_t units = 1000; unsigned char a8[8]; for (int i = 0; i < 8; ++i) a8[i] = (unsigned char)((units >> (8*i)) & 0xFF); tagp.insert(tagp.end(), a8, a8+8);
        std::vector<unsigned char> tagtlv; tagtlv.push_back((uint8_t)assets::OutExtType::ASSET_TAG); tagtlv.push_back((uint8_t)tagp.size()); tagtlv.insert(tagtlv.end(), tagp.begin(), tagp.end());
        asset_out.vExt = tagtlv;
    }
    mint.vout.push_back(asset_out);

    // Sign ICU input with ANYONECANPAY|ALL
    SignatureData sd;
    BOOST_CHECK(SignSignature(keystore, icu_spk, mint, /*nIn=*/0, /*amount=*/5 * COIN, SIGHASH_ALL | SIGHASH_ANYONECANPAY, sd));
    // Second input is OP_TRUE, no signature needed but set scriptSig
    mint.vin[1].scriptSig = CScript() << OP_TRUE;

    blockB.vtx.push_back(MakeTransactionRef(CTransaction(mint)));
    blockB.hashMerkleRoot = BlockMerkleRoot(blockB);

    CCoinsViewCache viewB(&chainstate.CoinsTip());
    BlockValidationState stB;
    uint256 hB = blockB.GetHash();
    CBlockIndex idxB(blockB);
    idxB.pprev = chainstate.m_chain.Tip();
    idxB.nHeight = chainstate.m_chain.Tip()->nHeight + 1;
    idxB.phashBlock = &hB;
    BOOST_CHECK(!chainstate.ConnectBlock(blockB, stB, &idxB, viewB, /*fJustCheck=*/true));
    BOOST_CHECK_EQUAL(stB.GetRejectReason(), "icu-invalid-sighash");
}

BOOST_FIXTURE_TEST_CASE(icu_sighash_anyonecanpay_false_positive_witness_data, TestChain100Setup)
{
    // The policy check for ANYONECANPAY on ICU inputs should ignore non-signature
    // witness data, even if it has the 0x80 bit set in its last byte.
    auto& chainstate = m_node.chainman->ActiveChainstate();

    // Prepare P2WSH ICU script that drops an auxiliary stack element and then returns true.
    const CScript witness_script = CScript() << OP_DROP << OP_TRUE;
    CScript icu_spk = GetScriptForDestination(WitnessV0ScriptHash(witness_script));

    // Register an asset with this ICU script.
    uint256 aid; memset(aid.data(), 0x33, aid.size());
    const uint32_t policy_bits = assets::MINT_ALLOWED | assets::BURN_ALLOWED;
    auto reg_tlv = test_util::BuildV1IssuerReg(aid, policy_bits, assets::SPK_DEFAULT_ALLOWED);

    CTxOut icu_out(5 * COIN, icu_spk);
    icu_out.vExt = reg_tlv;
    COutPoint coinbase_prev{m_coinbase_txns.at(0)->GetHash(), 0};
    CMutableTransaction reg = CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns.at(0)},
        /*inputs=*/{coinbase_prev},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{icu_out},
        /*submit=*/false);
    CreateAndProcessBlock({reg}, CScript() << OP_TRUE);

    AssetRegistryEntry reg_entry;
    BOOST_REQUIRE(chainstate.CoinsTip().ReadAssetPolicy(aid, reg_entry));

    // Assemble a mint transaction that rotates the ICU and mints an asset tag output.
    CMutableTransaction mint;
    mint.version = CTransaction::CURRENT_VERSION;
    mint.vin.resize(2);
    mint.vin[0].prevout = reg_entry.icu_outpoint;
    mint.vin[1].prevout = COutPoint{m_coinbase_txns.at(1)->GetHash(), 0};

    // Output 0: rotate ICU bond back to same script/value.
    mint.vout.emplace_back(5 * COIN, icu_spk);
    mint.vout[0].vExt = reg_tlv;

    // Output 1: asset tag spend (0.00001 BTC for example standard output).
    CKey beneficiary_key; beneficiary_key.MakeNewKey(true);
    CTxOut asset_out(1000, GetScriptForDestination(WitnessV0KeyHash(beneficiary_key.GetPubKey())));
    {
        std::vector<unsigned char> tag_payload;
        tag_payload.insert(tag_payload.end(), aid.begin(), aid.end());
        const uint64_t units = 1000;
        for (int i = 0; i < 8; ++i) {
            tag_payload.push_back((units >> (8 * i)) & 0xFF);
        }
        std::vector<unsigned char> tag_tlv;
        tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
        tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
        tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());
        asset_out.vExt = tag_tlv;
    }
    mint.vout.push_back(asset_out);

    // Provide change/funding output if needed to keep transaction balanced.
    const CAmount fee_input_value = m_coinbase_txns.at(1)->vout[0].nValue;
    const CAmount asset_value = mint.vout[1].nValue;
    const CAmount fee = 1000; // 1000 satoshis fee
    const CAmount change_value = fee_input_value - asset_value - fee;
    BOOST_REQUIRE(change_value >= 0);
    if (change_value > 0) {
        mint.vout.emplace_back(change_value, CScript() << OP_TRUE);
    }

    // Provide witness stack containing suspicious-looking non-signature data.
    std::vector<unsigned char> dummy(1, 0x80); // Last byte has ANYONECANPAY bit set.
    std::vector<unsigned char> ws_bytes(witness_script.begin(), witness_script.end());
    mint.vin[0].scriptWitness.stack = {dummy, ws_bytes};

    // Satisfy the second input (OP_TRUE coinbase spend).
    mint.vin[1].scriptSig = CScript() << OP_TRUE;

    // With new ICU guard, this transaction will be rejected due to stricter SIGHASH validation
    // for transactions with witness data that could be misinterpreted as ANYONECANPAY
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(CTransaction(mint)));
    // Expecting rejection due to new ICU sighash detection paradigm
    BOOST_CHECK_EQUAL(result.m_result_type, MempoolAcceptResult::ResultType::INVALID);
}

BOOST_AUTO_TEST_SUITE_END()
