#include <wallet/contract.h>

#include <addresstype.h>
#include <assets/asset.h>
#include <consensus/amount.h>
#include <uint256.h>
#include <boost/test/unit_test.hpp>
#include <key_io.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <span>

BOOST_AUTO_TEST_SUITE(wallet_repo_tests)

BOOST_AUTO_TEST_CASE(repo_offer_commitment_deterministic)
{
    using namespace wallet;

    RepoTerms terms;
    terms.principal_leg.is_native = false;
    terms.principal_leg.asset_id = uint256::ONE;
    terms.principal_leg.units = 1'000;
    terms.interest_leg.is_native = false;
    terms.interest_leg.asset_id = uint256::ONE;
    terms.interest_leg.units = 500;
    terms.collateral_leg.is_native = true;
    terms.collateral_leg.units = 2 * COIN;
    terms.maturity_height = 123456;
    terms.safety_k = 6;
    terms.reorg_conf = 2;

    std::array<unsigned char, 32> borrower_bytes{};
    borrower_bytes.fill(0x11);
    std::array<unsigned char, 32> lender_bytes{};
    lender_bytes.fill(0x22);

    const XOnlyPubKey borrower_key{std::span<const unsigned char>(borrower_bytes)};
    const XOnlyPubKey lender_key{std::span<const unsigned char>(lender_bytes)};

    const CTxDestination borrower_dest = WitnessV1Taproot(borrower_key);
    const CTxDestination lender_dest = WitnessV1Taproot(lender_key);

    const uint256 salt = uint256::ONE;

    RepoOfferRecord record1;
    record1.terms = terms;
    record1.borrower_dest = borrower_dest;
    record1.salt = salt;

    const uint256 commitment1 = ComputeRepoOfferCommitment(record1, lender_dest);

    RepoOfferRecord record2;
    record2.terms = terms;
    record2.borrower_dest = borrower_dest;
    record2.salt = salt;

    const uint256 commitment2 = ComputeRepoOfferCommitment(record2, lender_dest);
    BOOST_CHECK_EQUAL(commitment1, commitment2);

    const std::array<unsigned char, 32> altered_bytes = [] {
        std::array<unsigned char, 32> out{};
        out.fill(0x33);
        return out;
    }();
    const CTxDestination altered_borrower = WitnessV1Taproot(XOnlyPubKey(std::span<const unsigned char>(altered_bytes)));

    RepoOfferRecord record_alt;
    record_alt.terms = terms;
    record_alt.borrower_dest = altered_borrower;
    record_alt.salt = salt;

    const uint256 different_commitment = ComputeRepoOfferCommitment(record_alt, lender_dest);
    BOOST_CHECK(commitment1 != different_commitment);

    RepoTerms native_terms = terms;
    native_terms.principal_leg.is_native = true;
    native_terms.principal_leg.asset_id.SetNull();
    native_terms.principal_leg.units = 50'000; // sats
    native_terms.interest_leg.is_native = true;
    native_terms.interest_leg.asset_id.SetNull();
    native_terms.interest_leg.units = 5'000;

    RepoOfferRecord record_native;
    record_native.terms = native_terms;
    record_native.borrower_dest = borrower_dest;
    record_native.salt = salt;

    const uint256 native_commitment = ComputeRepoOfferCommitment(record_native, lender_dest);
    BOOST_CHECK(commitment1 != native_commitment);

    RepoTerms different_asset = terms;
    std::array<unsigned char, 32> other_asset_bytes{};
    other_asset_bytes.fill(0x44);
    different_asset.principal_leg.asset_id = uint256(std::span<const unsigned char>(other_asset_bytes));

    RepoOfferRecord record_diff;
    record_diff.terms = different_asset;
    record_diff.borrower_dest = borrower_dest;
    record_diff.salt = salt;

    const uint256 other_asset_commitment = ComputeRepoOfferCommitment(record_diff, lender_dest);
    BOOST_CHECK(other_asset_commitment != commitment1);
}

BOOST_AUTO_TEST_CASE(repo_asset_tag_tlv_structure)
{
    using namespace wallet;

    const uint256 asset_id = uint256::ONE;
    const uint64_t units = 123456789ULL;
    const std::vector<unsigned char> tlv = BuildAssetTagTlv(asset_id, units);

    BOOST_REQUIRE_GE(tlv.size(), 2);
    BOOST_CHECK_EQUAL(tlv[0], static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
    BOOST_CHECK_EQUAL(tlv[1], 32 + sizeof(uint64_t));
    BOOST_REQUIRE_EQUAL(tlv.size(), 2 + 32 + sizeof(uint64_t));

    std::vector<unsigned char> asset_bytes(asset_id.begin(), asset_id.end());
    std::vector<unsigned char> encoded_asset(tlv.begin() + 2, tlv.begin() + 34);
    BOOST_CHECK_EQUAL_COLLECTIONS(asset_bytes.begin(), asset_bytes.end(),
                                  encoded_asset.begin(), encoded_asset.end());

    const std::vector<unsigned char> encoded_units(tlv.begin() + 34, tlv.end());
    std::vector<unsigned char> expected_units = EncodeLE64(units);
    BOOST_CHECK_EQUAL_COLLECTIONS(expected_units.begin(), expected_units.end(),
                                  encoded_units.begin(), encoded_units.end());
}

BOOST_AUTO_TEST_CASE(repo_extract_taproot_key)
{
    using namespace wallet;

    std::array<unsigned char, 32> key_bytes{};
    key_bytes.fill(0x77);
    const XOnlyPubKey key{std::span<const unsigned char>(key_bytes)};

    const CTxDestination tap_dest = WitnessV1Taproot(key);
    auto extracted = ExtractTaprootKey(tap_dest);
    BOOST_REQUIRE(extracted.has_value());
    BOOST_CHECK_EQUAL_COLLECTIONS(key.begin(), key.end(), extracted->begin(), extracted->end());

    const std::vector<unsigned char> program(key.begin(), key.end());
    const CTxDestination unknown_dest = WitnessUnknown(1, program);
    extracted = ExtractTaprootKey(unknown_dest);
    BOOST_REQUIRE(extracted.has_value());
    BOOST_CHECK_EQUAL_COLLECTIONS(key.begin(), key.end(), extracted->begin(), extracted->end());

    const CTxDestination other_version = WitnessUnknown(2, program);
    BOOST_CHECK(!ExtractTaprootKey(other_version).has_value());
}

BOOST_AUTO_TEST_CASE(repo_encode_le64_endianness)
{
    using namespace wallet;

    const uint64_t value = 0x0102030405060708ULL;
    const std::vector<unsigned char> encoded = EncodeLE64(value);
    BOOST_REQUIRE_EQUAL(encoded.size(), sizeof(uint64_t));
    const std::vector<unsigned char> expected = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), encoded.begin(), encoded.end());

    const uint64_t zero = 0;
    const std::vector<unsigned char> zero_encoded = EncodeLE64(zero);
    BOOST_REQUIRE_EQUAL(zero_encoded.size(), sizeof(uint64_t));
    BOOST_CHECK(std::all_of(zero_encoded.begin(), zero_encoded.end(), [](unsigned char c) { return c == 0; }));
}

BOOST_AUTO_TEST_CASE(repo_asset_delivery_commitment_roundtrip)
{
    using namespace wallet;

    std::array<unsigned char, 32> key_bytes{};
    key_bytes.fill(0x55);
    const XOnlyPubKey key{std::span<const unsigned char>(key_bytes)};
    const CTxDestination dest = WitnessV1Taproot(key);
    const CScript script = GetScriptForDestination(dest);

    AssetDeliveryTemplate asset_tmpl;
    asset_tmpl.is_native = false;
    asset_tmpl.asset_id = uint256::ONE;
    asset_tmpl.units = 42;
    asset_tmpl.script_pubkey = script;
    asset_tmpl.vext = BuildAssetTagTlv(asset_tmpl.asset_id, asset_tmpl.units);
    asset_tmpl.commitment = ComputeAssetDeliveryCommitment(asset_tmpl);

    const uint256 direct = ComputeAssetDeliveryCommitment(
        asset_tmpl.is_native,
        asset_tmpl.asset_id,
        asset_tmpl.units,
        asset_tmpl.script_pubkey,
        asset_tmpl.vext);
    BOOST_CHECK_EQUAL(asset_tmpl.commitment, direct);

    AssetDeliveryTemplate native_tmpl;
    native_tmpl.is_native = true;
    native_tmpl.asset_id.SetNull();
    native_tmpl.units = 1000;
    native_tmpl.script_pubkey = script;
    native_tmpl.vext.clear();
    native_tmpl.commitment = ComputeAssetDeliveryCommitment(native_tmpl);

    const uint256 native_direct = ComputeAssetDeliveryCommitment(
        native_tmpl.is_native,
        native_tmpl.asset_id,
        native_tmpl.units,
        native_tmpl.script_pubkey,
        native_tmpl.vext);
    BOOST_CHECK_EQUAL(native_tmpl.commitment, native_direct);
    BOOST_CHECK(native_tmpl.commitment != asset_tmpl.commitment);
}

BOOST_AUTO_TEST_SUITE_END()
