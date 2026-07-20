// Copyright (c) 2024 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/test/unit_test.hpp>

#include <coins.h>
#include <consensus/amount.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <cstring>

BOOST_FIXTURE_TEST_SUITE(policy_covenant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(covenant_output_limit)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    CScript tap_script;
    tap_script << OP_OUTPUTMATCH_NATIVE << OP_DROP << OP_TRUE;
    std::vector<unsigned char> tap_bytes(tap_script.begin(), tap_script.end());
    std::vector<unsigned char> control_block(33, 0);
    control_block[0] = TAPROOT_LEAF_TAPSCRIPT;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>{}, tap_bytes, control_block};

    CScript spk = CScript() << OP_1 << std::vector<unsigned char>(32, 0x42);
    for (size_t i = 0; i < MAX_COVENANT_TX_OUTPUTS + 1; ++i) {
        tx.vout.emplace_back(CAmount{1000}, spk);
    }

    std::string reason;
    CFeeRate dust_relay_fee{DUST_RELAY_TX_FEE};
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, std::nullopt, /*permit_bare_multisig=*/true, dust_relay_fee, reason));
    BOOST_CHECK_EQUAL(reason, "too-many-covenant-outputs");
}

BOOST_AUTO_TEST_CASE(covenant_opcode_per_input_limit)
{
    // Create funding output with simple P2TR script.
    CMutableTransaction funding;
    funding.vout.emplace_back(CAmount{1000}, CScript() << OP_1 << std::vector<unsigned char>(32, 0x21));
    Txid funding_txid = Txid::FromUint256(funding.GetHash());

    // Add coin to view.
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    coins.AddCoin(COutPoint(funding_txid, 0), Coin(funding.vout[0], /*height=*/1, /*is_coinbase=*/false), false);

    // Spending transaction referencing the Taproot output.
    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint(funding_txid, 0));
    spend.vout.emplace_back(CAmount{900}, CScript() << OP_TRUE);

    // Witness stack simulating a tapscript path with nine OUTPUTMATCH instructions.
    CScript tapscript;
    uint256 script_hash;
    std::memset(script_hash.data(), 0x33, script_hash.size());
    for (unsigned int i = 0; i < MAX_OUTPUTMATCH_PER_INPUT + 1; ++i) {
        tapscript << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
        std::vector<unsigned char> amount(8);
        WriteLE64(amount.data(), 1);
        tapscript << amount;
        tapscript << OP_OUTPUTMATCH_NATIVE;
        tapscript << OP_DROP;
    }
    std::vector<unsigned char> script_bytes(tapscript.begin(), tapscript.end());
    std::vector<unsigned char> control_block(33, 0);
    control_block[0] = TAPROOT_LEAF_TAPSCRIPT;

    spend.vin[0].scriptWitness.stack = {
        std::vector<unsigned char>{},
        script_bytes,
        control_block
    };

    BOOST_CHECK(!IsWitnessStandard(CTransaction{spend}, coins));
}

BOOST_AUTO_TEST_SUITE_END()
