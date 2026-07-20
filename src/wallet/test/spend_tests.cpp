// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <assets/asset.h>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <key.h>
#include <policy/fees.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <psbt.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <test/util/asset_utils.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

namespace {

CTxOut MakeAssetOutput(const CScript& spk, unsigned char fill_byte, uint64_t units = 1)
{
    CTxOut out(1 * COIN, spk);
    std::vector<unsigned char> tlv;
    tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    tlv.push_back(40);
    for (int i = 0; i < 32; ++i) tlv.push_back(fill_byte);
    unsigned char amount_bytes[8];
    WriteLE64(amount_bytes, static_cast<uint64_t>(units));
    tlv.insert(tlv.end(), amount_bytes, amount_bytes + 8);
    out.vExt = std::move(tlv);
    return out;
}

}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    auto check_tx = [&wallet](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, 50 BTC each, to the wallet (total balance 200 BTC)
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO (150 BTC total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to 200 BTC, and the tx target is 299 BTC.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send 299 BTC from a wallet that only has 200 BTC. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the 299 BTC payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send 200 BTC.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 BTC)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 BTC.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_FIXTURE_TEST_CASE(icu_exclusion_from_auto_selection, TestChain100Setup)
{
    // Test that ICU (Issuer Credential UTXO) outputs are excluded from automatic coin selection.
    // This prevents "asset-bond-rotation" consensus failures from accidental ICU consumption.

    // Create a wallet with proper key
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Generate more blocks to make coinbase spendable and give wallet some coins
    for (int i = 0; i < 10; ++i) {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    }

    // Sync wallet with chain
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    }
    // SyncWithValidationInterfaceQueue() is not available in test context

    // Create a normal UTXO transaction
    CMutableTransaction tx_normal;
    tx_normal.vin.resize(1);
    tx_normal.vin[0].prevout = COutPoint(m_coinbase_txns[0]->GetHash(), 0);
    const CScript kWalletScript = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    tx_normal.vout.emplace_back(10 * COIN, kWalletScript);
    tx_normal.vout.emplace_back(39 * COIN, kWalletScript); // rest as change

    // Sign the normal transaction
    FillableSigningProvider keystore_normal;
    keystore_normal.AddKey(coinbaseKey);
    std::map<COutPoint, Coin> coins_normal;
    coins_normal[tx_normal.vin[0].prevout].out = m_coinbase_txns[0]->vout[0];
    std::map<int, bilingual_str> input_errors_normal;
    BOOST_CHECK(SignTransaction(tx_normal, &keystore_normal, coins_normal, SIGHASH_ALL, input_errors_normal));

    // Create a transaction with an ICU output (has IssuerReg TLV)
    CMutableTransaction mtx_icu;
    mtx_icu.vin.resize(1);
    mtx_icu.vin[0].prevout = COutPoint(m_coinbase_txns[1]->GetHash(), 0);

    // Create an ICU output with IssuerReg TLV
    CTxOut icu_out(5 * COIN, kWalletScript);

    // Build v1 IssuerReg TLV (deterministic 221 bytes with ZK+ICU sections)
    uint256 asset_id_icu;
    memset(asset_id_icu.data(), 0xAA, 32);
    std::vector<unsigned char> icu_tlv = test_util::BuildV1IssuerReg(asset_id_icu, 0x03, 0x1C);

    icu_out.vExt = icu_tlv;
    mtx_icu.vout.push_back(icu_out);

    // Add change output
    mtx_icu.vout.push_back(CTxOut(44 * COIN, kWalletScript));

    // Sign the ICU transaction
    FillableSigningProvider keystore;
    keystore.AddKey(coinbaseKey);
    std::map<COutPoint, Coin> coins_icu;
    coins_icu[mtx_icu.vin[0].prevout].out = m_coinbase_txns[1]->vout[0];
    std::map<int, bilingual_str> input_errors_icu;
    BOOST_CHECK(SignTransaction(mtx_icu, &keystore, coins_icu, SIGHASH_ALL, input_errors_icu));

    // Create a transaction with an asset-tagged output (type 0x01)
    CMutableTransaction mtx_asset;
    mtx_asset.vin.resize(1);
    mtx_asset.vin[0].prevout = COutPoint(m_coinbase_txns[2]->GetHash(), 0);

    CTxOut asset_out(6 * COIN, kWalletScript);
    std::vector<unsigned char> asset_tlv;
    asset_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
    asset_tlv.push_back(40); // 32 bytes asset id + 8 bytes amount
    for (int i = 0; i < 32; ++i) asset_tlv.push_back(0xBB);
    unsigned char amount_bytes[8];
    WriteLE64(amount_bytes, static_cast<uint64_t>(500000));
    asset_tlv.insert(asset_tlv.end(), amount_bytes, amount_bytes + 8);
    asset_out.vExt = asset_tlv;
    mtx_asset.vout.push_back(asset_out);
    // Add change output to keep transaction balanced
    mtx_asset.vout.push_back(CTxOut(43 * COIN, kWalletScript));

    FillableSigningProvider keystore_asset;
    keystore_asset.AddKey(coinbaseKey);
    std::map<COutPoint, Coin> coins_asset;
    coins_asset[mtx_asset.vin[0].prevout].out = m_coinbase_txns[2]->vout[0];
    std::map<int, bilingual_str> input_errors_asset;
    BOOST_CHECK(SignTransaction(mtx_asset, &keystore_asset, coins_asset, SIGHASH_ALL, input_errors_asset));

    // Mine all crafted transactions and add them to wallet properly
    CreateAndProcessBlock({tx_normal, mtx_icu, mtx_asset}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Properly sync wallet with chain so it recognizes the outputs
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());

        // Add the transactions to the wallet as confirmed
        wallet->AddToWallet(MakeTransactionRef(tx_normal),
                           TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(),
                                          m_node.chainman->ActiveChain().Height(), 1});
        wallet->AddToWallet(MakeTransactionRef(mtx_icu),
                           TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(),
                                          m_node.chainman->ActiveChain().Height(), 2});
        wallet->AddToWallet(MakeTransactionRef(mtx_asset),
                           TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(),
                                          m_node.chainman->ActiveChain().Height(), 3});
    }

    {
        LOCK(wallet->cs_wallet);
        const auto asset_meta = wallet->GetAssetMetadata(COutPoint(mtx_asset.GetHash(), 0));
        BOOST_REQUIRE(asset_meta.has_value());
        BOOST_CHECK_EQUAL(asset_meta->asset_id.GetHex(), std::string(64, 'b'));
        BOOST_CHECK(!asset_meta->is_issuer_credential);
        BOOST_CHECK(!asset_meta->has_ticker);
        BOOST_CHECK(!asset_meta->has_decimals);

        const auto icu_meta = wallet->GetAssetMetadata(COutPoint(mtx_icu.GetHash(), 0));
        BOOST_REQUIRE(icu_meta.has_value());
        BOOST_CHECK(icu_meta->is_issuer_credential);
        BOOST_CHECK_EQUAL(icu_meta->asset_id.GetHex(), std::string(64, 'a'));
        BOOST_CHECK(!icu_meta->has_ticker);
        BOOST_CHECK(!icu_meta->has_decimals);
    }

    // Store references for later use in tests
    auto tx_icu_ref = MakeTransactionRef(mtx_icu);

    // Test 1: Automatic selection should NOT include ICU
    {
        CCoinControl coin_control;
        CoinFilterParams filter;

        auto available = AvailableCoins(*wallet, &coin_control, /*feerate=*/std::nullopt, filter);

        // Should find normal UTXOs but not the ICU
        bool found_icu = false;
        bool found_asset = false;
        int normal_count = 0;

        for (const auto& coin : available.All()) {
            if (!coin.txout.vExt.empty() && assets::ParseIssuerReg(coin.txout.vExt)) {
                found_icu = true;
            } else if (!coin.txout.vExt.empty() && assets::ParseAssetTag(coin.txout.vExt)) {
                found_asset = true;
            } else {
                normal_count++;
            }
        }

        BOOST_CHECK(!found_icu); // ICU should NOT be found in automatic selection
        BOOST_CHECK(!found_asset); // Asset-tagged UTXOs should NOT be auto-selected
        BOOST_CHECK_GT(normal_count, 0); // Should find normal UTXOs
    }

    // Allow ICU selection via coin control flag
    {
        CCoinControl coin_control;
        coin_control.m_allow_icu_selection = true;
        CoinFilterParams filter;
        CoinsResult available;
        {
            LOCK(wallet->cs_wallet);
            available = AvailableCoins(*wallet, &coin_control, /*feerate=*/std::nullopt, filter);
        }
        bool found_icu = false;
        for (const auto& coin : available.All()) {
            if (assets::ParseIssuerReg(coin.txout.vExt)) {
                found_icu = true;
                break;
            }
        }
        BOOST_CHECK(found_icu);
    }

    uint256 asset_id;
    {
        LOCK(wallet->cs_wallet);
        const auto meta = wallet->GetAssetMetadata(COutPoint(mtx_asset.GetHash(), 0));
        BOOST_REQUIRE(meta.has_value());
        asset_id = meta->asset_id;
    }

    // Require matching asset id to surface asset-tagged UTXOs
    {
        CCoinControl coin_control;
        coin_control.m_required_asset_id = asset_id;
        CoinFilterParams filter;
        CoinsResult available;
        {
            LOCK(wallet->cs_wallet);
            available = AvailableCoins(*wallet, &coin_control, /*feerate=*/std::nullopt, filter);
        }
        bool found_asset = false;
        for (const auto& coin : available.All()) {
            if (assets::ParseAssetTag(coin.txout.vExt)) {
                found_asset = true;
                break;
            }
        }
        BOOST_CHECK(found_asset);
    }

    // Asset id mismatch must continue to hide asset UTXOs
    {
        CCoinControl coin_control;
        coin_control.m_required_asset_id = uint256::ONE;
        CoinFilterParams filter;
        CoinsResult available;
        {
            LOCK(wallet->cs_wallet);
            available = AvailableCoins(*wallet, &coin_control, /*feerate=*/std::nullopt, filter);
        }
        bool found_asset = false;
        for (const auto& coin : available.All()) {
            if (assets::ParseAssetTag(coin.txout.vExt)) {
                found_asset = true;
                break;
            }
        }
        BOOST_CHECK(!found_asset);
    }

    // Test 2: Verify ICU can be explicitly selected for spending (but not through AvailableCoins)
    // This test verifies that ICUs can be used when explicitly selected in a transaction
    {
        // Create a transaction that explicitly spends the ICU
        CMutableTransaction tx_spend_icu;
        tx_spend_icu.vin.resize(1);
        tx_spend_icu.vin[0].prevout = COutPoint(tx_icu_ref->GetHash(), 0); // Explicitly use ICU output

        tx_spend_icu.vout.push_back(CTxOut(4 * COIN, kWalletScript));

        // Sign the transaction - this should work fine
        FillableSigningProvider keystore_explicit;
        keystore_explicit.AddKey(coinbaseKey);
        std::map<COutPoint, Coin> coins_explicit;
        coins_explicit[tx_spend_icu.vin[0].prevout].out = tx_icu_ref->vout[0];
        std::map<int, bilingual_str> input_errors_explicit;

        // This should succeed - ICUs can be explicitly spent
        BOOST_CHECK(SignTransaction(tx_spend_icu, &keystore_explicit, coins_explicit, SIGHASH_ALL, input_errors_explicit));
    }

    // Test 3: FundTransaction should not select ICU for fees
    {
        // Create transaction with empty inputs and outputs for FundTransaction
        CMutableTransaction tx_to_fund;
        // FundTransaction expects empty vout and will add outputs via recipients
        std::vector<CRecipient> recipients;
        CRecipient recipient;
        recipient.dest = PKHash(coinbaseKey.GetPubKey());
        recipient.nAmount = 2 * COIN;
        recipient.fSubtractFeeFromAmount = false;
        recipients.push_back(recipient);

        CCoinControl coin_control;
        auto result = FundTransaction(*wallet, tx_to_fund, recipients, /*change_pos=*/std::nullopt,
                                      /*lockUnspents=*/false, coin_control);

        BOOST_CHECK(result.has_value());
        if (result) {
            // Check that none of the selected inputs are ICUs or asset-tagged outputs
            for (const auto& input : result->tx->vin) {
                // Look up the coin from wallet's view
                const CWalletTx* wtx = wallet->GetWalletTx(input.prevout.hash);
                if (wtx && input.prevout.n < wtx->tx->vout.size()) {
                    const CTxOut& out = wtx->tx->vout[input.prevout.n];
                    BOOST_CHECK(!assets::ParseIssuerReg(out.vExt));
                    BOOST_CHECK(!assets::ParseAssetTag(out.vExt));
                }
            }
        }
    }

    // Test 4: Reapplying output extensions after funding preserves TLVs
    {
        CMutableTransaction template_tx;
        template_tx.vout = mtx_asset.vout;
        const auto snapshots = CollectOutputExtensionSnapshots(template_tx);
        BOOST_REQUIRE_EQUAL(snapshots.size(), 1U);

        std::vector<CRecipient> recipients;
        for (const auto& out : template_tx.vout) {
            CTxDestination dest;
            BOOST_CHECK(ExtractDestination(out.scriptPubKey, dest));
            CRecipient recipient;
            recipient.dest = dest;
            recipient.nAmount = out.nValue;
            recipient.fSubtractFeeFromAmount = false;
            recipients.push_back(recipient);
        }

        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = true;

        CMutableTransaction funding_request;
        auto fund_res = FundTransaction(*wallet, funding_request, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
        BOOST_REQUIRE(fund_res);

        CMutableTransaction funded_tx(*fund_res->tx);
        BOOST_CHECK(std::none_of(funded_tx.vout.begin(), funded_tx.vout.end(), [](const CTxOut& txo) { return !txo.vExt.empty(); }));

        const bool reapplied = ReapplyOutputExtensionSnapshots(snapshots, funded_tx);
        BOOST_CHECK(reapplied);

        const std::vector<CTxOut> funded_outputs(funded_tx.vout.begin(), funded_tx.vout.end());
        const AssetIdScanResult restored_scan = ScanAssetIds(funded_outputs);
        BOOST_CHECK(restored_scan.asset_id.has_value());
        BOOST_CHECK(!restored_scan.conflict);
    }

    // Test 5: ScanAssetIds detects conflicts across outputs
    {
        std::vector<CTxOut> mismatched_outputs;
        mismatched_outputs.push_back(mtx_asset.vout[0]);
        CTxOut altered = mtx_asset.vout[0];
        if (altered.vExt.size() > 2) {
            altered.vExt[2] ^= 0x01;
        }
        mismatched_outputs.push_back(altered);
        const AssetIdScanResult scan = ScanAssetIds(mismatched_outputs);
        BOOST_CHECK(scan.conflict);
    }
}

BOOST_FIXTURE_TEST_CASE(multi_asset_transaction_handling, TestChain100Setup)
{
    const CScript spk = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    std::vector<CTxOut> mixed_outputs{MakeAssetOutput(spk, 0xAA), MakeAssetOutput(spk, 0xBB)};
    const auto scan = ScanAssetIds(mixed_outputs);
    BOOST_CHECK(scan.conflict);

    std::vector<CTxOut> uniform_outputs{MakeAssetOutput(spk, 0xCC), MakeAssetOutput(spk, 0xCC)};
    const auto uniform_scan = ScanAssetIds(uniform_outputs);
    BOOST_CHECK(uniform_scan.asset_id.has_value());
    BOOST_CHECK(!uniform_scan.conflict);

    auto make_template = [&](unsigned char fill_byte) {
        CMutableTransaction tmpl;
        tmpl.vout.push_back(MakeAssetOutput(spk, fill_byte));
        return tmpl;
    };

    auto single_snapshot = CollectOutputExtensionSnapshots(make_template(0xAA));
    auto second_snapshot = CollectOutputExtensionSnapshots(make_template(0xBB));
    single_snapshot.insert(single_snapshot.end(), second_snapshot.begin(), second_snapshot.end());

    CMutableTransaction funded;
    funded.vout.resize(2);
    funded.vout[0] = CTxOut(1 * COIN, spk);
    funded.vout[1] = CTxOut(1 * COIN, spk);
    BOOST_CHECK(ReapplyOutputExtensionSnapshots(single_snapshot, funded));
    const auto post_scan = ScanAssetIds({funded.vout.begin(), funded.vout.end()});
    BOOST_CHECK(post_scan.conflict);
}

BOOST_FIXTURE_TEST_CASE(asset_funding_error_messages, TestChain100Setup)
{
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    const CScript spk = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CMutableTransaction mint_tx;
    mint_tx.vin.resize(1);
    mint_tx.vin[0].prevout = COutPoint(m_coinbase_txns[1]->GetHash(), 0);
    mint_tx.vout.push_back(MakeAssetOutput(spk, 0xAA, /*units=*/5));
    // Add a tiny BTC output that can't fund any meaningful transaction
    mint_tx.vout.push_back(CTxOut(1000, spk));  // 0.00001 BTC, too small for fees

    FillableSigningProvider keystore;
    keystore.AddKey(coinbaseKey);
    std::map<COutPoint, Coin> coins_mint;
    coins_mint[mint_tx.vin[0].prevout].out = m_coinbase_txns[1]->vout[0];
    std::map<int, bilingual_str> mint_errors;
    BOOST_REQUIRE(SignTransaction(mint_tx, &keystore, coins_mint, SIGHASH_ALL, mint_errors));
    CreateAndProcessBlock({mint_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    {
        LOCK(wallet->cs_wallet);
        const auto& chain = m_node.chainman->ActiveChain();
        wallet->SetLastBlockProcessed(chain.Height(), chain.Tip()->GetBlockHash());
        wallet->AddToWallet(MakeTransactionRef(mint_tx),
                            TxStateConfirmed{chain.Tip()->GetBlockHash(), chain.Height(), 1});
    }

    CMutableTransaction template_tx;
    template_tx.vout.push_back(MakeAssetOutput(spk, 0xBB));
    const auto snapshots = CollectOutputExtensionSnapshots(template_tx);

    std::vector<CRecipient> recipients;
    for (const auto& snap : snapshots) {
        CTxDestination dest;
        BOOST_REQUIRE(ExtractDestination(snap.script_pub_key, dest));
        recipients.push_back(CRecipient{dest, snap.value, /*subtract_fee=*/false});
    }

    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;  // Let it try to find coins
    // Create asset ID filled with 0xBB bytes (same as MakeAssetOutput(spk, 0xBB))
    std::string bb_hex;
    bb_hex.reserve(64);
    for (int i = 0; i < 32; ++i) {
        bb_hex += "bb";
    }
    auto required_asset = uint256::FromHex(bb_hex);
    BOOST_REQUIRE(required_asset);
    coin_control.m_required_asset_id = *required_asset;

    auto res = FundTransaction(*wallet, CMutableTransaction{}, recipients, std::nullopt, false, coin_control);
    BOOST_CHECK(!res);
    const auto err = util::ErrorString(res);
    BOOST_CHECK(err.original.find("Insufficient funds for asset") != std::string::npos);

    std::vector<CTxOut> outputs;
    outputs.push_back(CTxOut(0, CScript{}));
    const auto empty_scan = ScanAssetIds(outputs);
    BOOST_CHECK(!empty_scan.asset_id);
    BOOST_CHECK(!empty_scan.conflict);

    CTxOut malformed(1 * COIN, GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())));
    malformed.vExt = {static_cast<uint8_t>(assets::OutExtType::ASSET_TAG), 0x01};
    const auto malformed_scan = ScanAssetIds({malformed});
    BOOST_CHECK(!malformed_scan.asset_id);
    BOOST_CHECK(!malformed_scan.conflict);
}

BOOST_FIXTURE_TEST_CASE(psbt_asset_metadata_preservation, TestChain100Setup)
{
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    const CScript spk = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    CMutableTransaction mint_tx;
    mint_tx.vin.resize(1);
    mint_tx.vin[0].prevout = COutPoint(m_coinbase_txns[1]->GetHash(), 0);
    mint_tx.vout.push_back(MakeAssetOutput(spk, 0xAD, /*units=*/7));
    mint_tx.vout.push_back(CTxOut(m_coinbase_txns[1]->vout[0].nValue - 1 * COIN, spk));

    FillableSigningProvider keystore;
    keystore.AddKey(coinbaseKey);
    std::map<COutPoint, Coin> coins_mint;
    coins_mint[mint_tx.vin[0].prevout].out = m_coinbase_txns[1]->vout[0];
    std::map<int, bilingual_str> mint_errors;
    BOOST_REQUIRE(SignTransaction(mint_tx, &keystore, coins_mint, SIGHASH_ALL, mint_errors));
    CreateAndProcessBlock({mint_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    {
        LOCK(wallet->cs_wallet);
        const auto& chain = m_node.chainman->ActiveChain();
        wallet->SetLastBlockProcessed(chain.Height(), chain.Tip()->GetBlockHash());
        wallet->AddToWallet(MakeTransactionRef(mint_tx),
                            TxStateConfirmed{chain.Tip()->GetBlockHash(), chain.Height(), 1});
    }

    CMutableTransaction template_tx;
    template_tx.vout.push_back(MakeAssetOutput(spk, 0xAD));

    const auto snapshots = CollectOutputExtensionSnapshots(template_tx);
    BOOST_REQUIRE_EQUAL(snapshots.size(), 1U);

    std::vector<CRecipient> recipients;
    recipients.reserve(snapshots.size());
    for (const auto& snap : snapshots) {
        CTxDestination dest;
        BOOST_REQUIRE(ExtractDestination(snap.script_pub_key, dest));
        recipients.push_back(CRecipient{dest, snap.value, /*subtract_fee=*/false});
    }

    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    std::string ad_hex;
    ad_hex.reserve(64);
    for (int i = 0; i < 32; ++i) {
        ad_hex += "ad";
    }
    auto required_asset = uint256::FromHex(ad_hex);
    BOOST_REQUIRE(required_asset);
    coin_control.m_required_asset_id = *required_asset;

    CMutableTransaction funding_request;
    auto fund_res = FundTransaction(*wallet, funding_request, recipients, std::nullopt, /*lockUnspents=*/false, coin_control);
    BOOST_REQUIRE(fund_res);

    CMutableTransaction funded(*fund_res->tx);
    BOOST_CHECK(ReapplyOutputExtensionSnapshots(snapshots, funded));

    PartiallySignedTransaction psbtx(funded);
    bool complete{false};
    const auto err = wallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
    BOOST_CHECK(!err);
    BOOST_CHECK(complete);

    auto collect_ext = [](const std::vector<CTxOut>& vouts) {
        std::vector<std::vector<unsigned char>> ext;
        for (const auto& out : vouts) {
            if (!out.vExt.empty()) ext.push_back(out.vExt);
        }
        return ext;
    };

    BOOST_REQUIRE(psbtx.tx);
    const auto funded_ext = collect_ext(funded.vout);
    const auto psbt_ext = collect_ext(psbtx.tx->vout);
    auto vec_to_hex = [](const std::vector<std::vector<unsigned char>>& vec) {
        std::vector<std::string> out;
        out.reserve(vec.size());
        for (const auto& bytes : vec) {
            out.push_back(HexStr(bytes));
        }
        return out;
    };

    const auto funded_hex = vec_to_hex(funded_ext);
    const auto psbt_hex = vec_to_hex(psbt_ext);
    BOOST_CHECK_EQUAL_COLLECTIONS(funded_hex.begin(), funded_hex.end(), psbt_hex.begin(), psbt_hex.end());

    CMutableTransaction final_tx;
    BOOST_CHECK(FinalizeAndExtractPSBT(psbtx, final_tx));
    const auto final_ext = collect_ext(final_tx.vout);
    const auto final_hex = vec_to_hex(final_ext);
    BOOST_CHECK_EQUAL_COLLECTIONS(funded_hex.begin(), funded_hex.end(), final_hex.begin(), final_hex.end());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
