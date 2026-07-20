// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <clientversion.h>
#include <streams.h>
#include <uint256.h>
#include <wallet/contract.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(walletdb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(walletdb_readkeyvalue)
{
    /**
     * When ReadKeyValue() reads from either a "key" or "wkey" it first reads the DataStream into a
     * CPrivKey or CWalletKey respectively and then reads a hash of the pubkey and privkey into a uint256.
     * Wallets from 0.8 or before do not store the pubkey/privkey hash, trying to read the hash from old
     * wallets throws an exception, for backwards compatibility this read is wrapped in a try block to
     * silently fail. The test here makes sure the type of exception thrown from DataStream::read()
     * matches the type we expect, otherwise we need to update the "key"/"wkey" exception type caught.
     */
    DataStream ssValue{};
    uint256 dummy;
    BOOST_CHECK_THROW(ssValue >> dummy, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(crosschain_record_serialization_roundtrip)
{
    CrossChainRecord record;
    record.swap_id = "swap-uuid-1234";
    record.offer_id = "offer-uuid-5678";
    record.state = CrossChainState::FUNDING_PREPARED;
    record.payload_json = R"({"schema":"cross_chain_spot_v1","id":"test"})";
    record.local_role = "maker";
    record.counterparty_pubkey = "npub1counterparty";
    record.external_chain = CrossChainKind::ETHEREUM;
    record.adapter = CrossChainAdapter::ETH_HTLC_V1;
    record.funding_order = CrossChainFundingOrder::EXTERNAL_FIRST;
    record.tsc_funding_txid = uint256::ONE;
    record.external_funding_txid = std::nullopt;
    record.adaptor_secret_ref = "key-ref-123";
    record.refund_artifact = "refund-data";
    record.external_conf_depth = 6;
    record.tsc_conf_depth = 1;
    record.fee_escalation_level = 2;
    record.oracle_attestation = "attestation-bytes";
    record.created_time = 1700000000;
    record.updated_time = 1700003600;

    // Serialize
    DataStream ss{};
    ss << record;

    // Deserialize
    CrossChainRecord decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.swap_id, "swap-uuid-1234");
    BOOST_CHECK_EQUAL(decoded.offer_id, "offer-uuid-5678");
    BOOST_CHECK(decoded.state == CrossChainState::FUNDING_PREPARED);
    BOOST_CHECK_EQUAL(decoded.payload_json, record.payload_json);
    BOOST_CHECK_EQUAL(decoded.local_role, "maker");
    BOOST_CHECK_EQUAL(decoded.counterparty_pubkey, "npub1counterparty");
    BOOST_CHECK(decoded.external_chain == CrossChainKind::ETHEREUM);
    BOOST_CHECK(decoded.adapter == CrossChainAdapter::ETH_HTLC_V1);
    BOOST_CHECK(decoded.funding_order == CrossChainFundingOrder::EXTERNAL_FIRST);
    BOOST_CHECK(decoded.tsc_funding_txid.has_value());
    BOOST_CHECK_EQUAL(*decoded.tsc_funding_txid, uint256::ONE);
    BOOST_CHECK(!decoded.external_funding_txid.has_value());
    BOOST_CHECK_EQUAL(decoded.adaptor_secret_ref, "key-ref-123");
    BOOST_CHECK_EQUAL(decoded.refund_artifact, "refund-data");
    BOOST_CHECK_EQUAL(decoded.external_conf_depth, 6u);
    BOOST_CHECK_EQUAL(decoded.tsc_conf_depth, 1u);
    BOOST_CHECK_EQUAL(decoded.fee_escalation_level, 2u);
    BOOST_CHECK_EQUAL(decoded.oracle_attestation, "attestation-bytes");
    BOOST_CHECK_EQUAL(decoded.created_time, 1700000000);
    BOOST_CHECK_EQUAL(decoded.updated_time, 1700003600);
}

BOOST_AUTO_TEST_CASE(crosschain_record_empty_optionals)
{
    CrossChainRecord record;
    record.swap_id = "swap-empty";
    record.state = CrossChainState::DRAFT;
    // Leave all optionals empty

    DataStream ss{};
    ss << record;

    CrossChainRecord decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.swap_id, "swap-empty");
    BOOST_CHECK(!decoded.tsc_funding_txid.has_value());
    BOOST_CHECK(!decoded.external_funding_txid.has_value());
    BOOST_CHECK(decoded.state == CrossChainState::DRAFT);
    BOOST_CHECK(decoded.adaptor_secret_ref.empty());
}

BOOST_AUTO_TEST_CASE(crosschain_state_transition_validation)
{
    using S = CrossChainState;

    // Valid transitions
    BOOST_CHECK(IsValidCrossChainTransition(S::DRAFT, S::POSTED));
    BOOST_CHECK(IsValidCrossChainTransition(S::POSTED, S::MATCHED));
    BOOST_CHECK(IsValidCrossChainTransition(S::CLAIM_READY, S::CLAIM_BROADCAST));
    BOOST_CHECK(IsValidCrossChainTransition(S::CLAIM_BROADCAST, S::EMERGENCY_CLAIM));
    BOOST_CHECK(IsValidCrossChainTransition(S::REFUND_READY, S::REFUND_BROADCAST));

    // Invalid: impossible jumps
    BOOST_CHECK(!IsValidCrossChainTransition(S::DRAFT, S::CLAIM_BROADCAST));
    BOOST_CHECK(!IsValidCrossChainTransition(S::POSTED, S::TERMS_FINALIZED));

    // Invalid: can't leave terminal states
    BOOST_CHECK(!IsValidCrossChainTransition(S::COMPLETED, S::DRAFT));
    BOOST_CHECK(!IsValidCrossChainTransition(S::REFUNDED, S::DRAFT));
    BOOST_CHECK(!IsValidCrossChainTransition(S::ABORTED, S::DRAFT));

    // Invalid: we-funded can't abort directly
    BOOST_CHECK(!IsValidCrossChainTransition(S::LOCAL_LOCK_CONFIRMED, S::ABORTED));
    BOOST_CHECK(!IsValidCrossChainTransition(S::CLAIM_READY, S::ABORTED));

    // Invalid: can't abort after secret reveal
    BOOST_CHECK(!IsValidCrossChainTransition(S::CLAIM_BROADCAST, S::ABORTED));

    // Valid: counterparty-only funded can abort
    BOOST_CHECK(IsValidCrossChainTransition(S::COUNTERPARTY_LOCK_SEEN, S::ABORTED));
    BOOST_CHECK(IsValidCrossChainTransition(S::COUNTERPARTY_LOCK_CONFIRMED, S::ABORTED));

    // Valid: pre-funding can abort
    BOOST_CHECK(IsValidCrossChainTransition(S::FUNDING_PREPARED, S::ABORTED));
}

BOOST_AUTO_TEST_CASE(settlement_profile_serialization_roundtrip)
{
    SettlementProfile profile;
    profile.label = "My BTC cold wallet";
    profile.chain = CrossChainKind::BTC;
    profile.address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    profile.signer_ref = "derived:auto";
    profile.preferred_asset = "BTC";
    profile.fee_speed = "normal";

    DataStream ss{};
    ss << profile;

    SettlementProfile decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.label, "My BTC cold wallet");
    BOOST_CHECK(decoded.chain == CrossChainKind::BTC);
    BOOST_CHECK_EQUAL(decoded.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    BOOST_CHECK_EQUAL(decoded.signer_ref, "derived:auto");
    BOOST_CHECK_EQUAL(decoded.preferred_asset, "BTC");
    BOOST_CHECK_EQUAL(decoded.fee_speed, "normal");
}

BOOST_AUTO_TEST_CASE(settlement_profile_eth)
{
    SettlementProfile profile;
    profile.label = "ETH hot";
    profile.chain = CrossChainKind::ETHEREUM;
    profile.address = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
    profile.signer_ref = "imported:eth-key-1";
    profile.preferred_asset = "USDT";
    profile.fee_speed = "fast";

    DataStream ss{};
    ss << profile;

    SettlementProfile decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.label, "ETH hot");
    BOOST_CHECK(decoded.chain == CrossChainKind::ETHEREUM);
    BOOST_CHECK_EQUAL(decoded.signer_ref, "imported:eth-key-1");
    BOOST_CHECK_EQUAL(decoded.fee_speed, "fast");
}

BOOST_AUTO_TEST_CASE(crosschain_all_states_roundtrip)
{
    // Verify every state value survives serialization
    for (uint8_t s = 0; s <= static_cast<uint8_t>(CrossChainState::ABORTED); ++s) {
        CrossChainRecord record;
        record.swap_id = "swap-state-" + std::to_string(s);
        record.state = static_cast<CrossChainState>(s);

        DataStream ss{};
        ss << record;

        CrossChainRecord decoded;
        ss >> decoded;

        BOOST_CHECK(decoded.state == static_cast<CrossChainState>(s));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
