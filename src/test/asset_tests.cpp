// Unit tests for asset TLV parsing and basic validation

#include <boost/test/unit_test.hpp>

#include <assets/asset.h>
#include <assets/registry.h>            // ScalarRecord
#include <consensus/scalar_cfd.h>       // ResolveScalarFixing / ScalarCfdFixingBuried (Slice 2)
#include <outputtype.h>
#include <primitives/transaction.h> // ValidateSingleTLV
#include <serialize.h>
#include <streams.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <numeric>
#include <optional>

#ifdef ENABLE_WALLET
#include <random.h>
#include <wallet/keywrap_utils.h>
#endif

BOOST_AUTO_TEST_SUITE(asset_tests)

static std::vector<unsigned char> TLV(uint8_t type, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> result;
    result.push_back(type);

    // Write compact size manually
    if (payload.size() < 253) {
        result.push_back(static_cast<unsigned char>(payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        result.push_back(253);
        result.push_back(payload.size() & 0xFF);
        result.push_back((payload.size() >> 8) & 0xFF);
    } else {
        // For larger sizes, would need more bytes
        result.push_back(254);
        for (int i = 0; i < 4; ++i) {
            result.push_back((payload.size() >> (i * 8)) & 0xFF);
        }
    }

    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

// Helper to build v1 IssuerReg payload (format_version=1, always includes ZK+ICU sections)
static std::vector<unsigned char> BuildV1IssuerReg(
    const uint256& asset_id,
    uint32_t policy_bits,
    uint16_t allowed_spk,
    const std::string& ticker = "",
    uint8_t decimals = 0xFF,
    uint64_t unlock_fees = std::numeric_limits<uint64_t>::max())
{
    std::vector<unsigned char> payload;

    // Header
    payload.insert(payload.end(), asset_id.begin(), asset_id.end());
    unsigned char pb[4]; WriteLE32(pb, policy_bits); payload.insert(payload.end(), pb, pb+4);
    unsigned char ab[2]; WriteLE16(ab, allowed_spk); payload.insert(payload.end(), ab, ab+2);
    payload.push_back(assets::ISSUER_REG_FORMAT_V1); // format_version

    // Ticker
    payload.push_back(static_cast<uint8_t>(ticker.size()));
    payload.insert(payload.end(), ticker.begin(), ticker.end());

    // Decimals
    payload.push_back(decimals);

    // Unlock fees
    unsigned char ub[8]; WriteLE64(ub, unlock_fees); payload.insert(payload.end(), ub, ub+8);

    // ZK section (76 bytes, all zeros for minimal test) - ZK Whitelist Hardening update
    for (int i = 0; i < 76; ++i) payload.push_back(0);

    // ICU section (129 bytes with icu_visibility, all zeros for minimal test)
    for (int i = 0; i < 129; ++i) payload.push_back(0);

    return payload;
}

// Helper to build a v2 IssuerReg payload: v1 layout with format_version flipped
// to v2 and a trailing 32-byte compliance_delegate_asset_id.
static std::vector<unsigned char> BuildV2IssuerReg(
    const uint256& asset_id,
    uint32_t policy_bits,
    uint16_t allowed_spk,
    const uint256& delegate)
{
    auto payload = BuildV1IssuerReg(asset_id, policy_bits, allowed_spk);
    // format_version byte sits at offset 32 (asset_id) + 4 (policy_bits) + 2 (allowed_spk) = 38.
    payload[38] = assets::ISSUER_REG_FORMAT_V2;
    payload.insert(payload.end(), delegate.begin(), delegate.end());
    return payload;
}

BOOST_AUTO_TEST_CASE(parse_asset_tag_valid)
{
    uint256 aid; memset(aid.data(), 0x11, aid.size());
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), aid.begin(), aid.end());
    unsigned char abuf[8]; WriteLE64(abuf, 12345); payload.insert(payload.end(), abuf, abuf+8);
    unsigned char fbuf[4]; WriteLE32(fbuf, 7); payload.insert(payload.end(), fbuf, fbuf+4);
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG), payload);
    auto tag = assets::ParseAssetTag(tlv);
    BOOST_REQUIRE(tag.has_value());
    BOOST_CHECK(tag->id == aid);
    BOOST_CHECK_EQUAL(tag->amount, 12345);
    BOOST_CHECK_EQUAL(tag->flags, 7);
}

BOOST_AUTO_TEST_CASE(parse_asset_tag_invalid)
{
    // Too short payload
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG), std::vector<unsigned char>(10, 0x00));
    auto tag = assets::ParseAssetTag(tlv);
    BOOST_CHECK(!tag.has_value());
}

BOOST_AUTO_TEST_CASE(parse_asset_tag_rejects_zero_id)
{
    uint256 aid{}; // zero-initialized
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), aid.begin(), aid.end());
    unsigned char abuf[8]; WriteLE64(abuf, 500); payload.insert(payload.end(), abuf, abuf + 8);
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG), payload);
    BOOST_CHECK(!assets::ParseAssetTag(tlv).has_value());
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_valid)
{
    uint256 aid; memset(aid.data(), 0x22, aid.size());
    auto payload = BuildV1IssuerReg(
        aid,
        0x0003u, // policy_bits
        assets::SPK_DEFAULT_ALLOWED, // allowed_spk_families
        "", // no ticker
        0xFF, // no decimals
        std::numeric_limits<uint64_t>::max() // no unlock_fees
    );
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    auto reg = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(reg.has_value());
    BOOST_CHECK(reg->asset_id == aid);
    BOOST_CHECK_EQUAL(reg->policy_bits, 0x0003u);
    BOOST_CHECK_EQUAL(reg->allowed_spk_families, assets::SPK_DEFAULT_ALLOWED);
    BOOST_CHECK_EQUAL(reg->format_version, assets::ISSUER_REG_FORMAT_V1);
    // A v1 reg always parses with a null delegate pointer.
    BOOST_CHECK(reg->compliance_delegate_asset_id.IsNull());
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v2_with_delegate)
{
    uint256 aid; memset(aid.data(), 0x22, aid.size());
    uint256 delegate; memset(delegate.data(), 0xD1, delegate.size());
    auto payload = BuildV2IssuerReg(aid, 0x0003u, assets::SPK_DEFAULT_ALLOWED, delegate);
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    auto reg = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(reg.has_value());
    BOOST_CHECK_EQUAL(reg->format_version, assets::ISSUER_REG_FORMAT_V2);
    BOOST_CHECK(reg->compliance_delegate_asset_id == delegate);
    BOOST_CHECK(reg->asset_id == aid);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v2_null_delegate_rejected)
{
    // v2 must carry a non-null delegate; "self" is always v1.
    uint256 aid; memset(aid.data(), 0x22, aid.size());
    uint256 zero{};
    auto payload = BuildV2IssuerReg(aid, 0x0003u, assets::SPK_DEFAULT_ALLOWED, zero);
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    BOOST_CHECK(!assets::ParseIssuerReg(tlv).has_value());
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v2_truncated_rejected)
{
    // format byte says v2 but the 32-byte delegate suffix is missing -> malformed.
    uint256 aid; memset(aid.data(), 0x22, aid.size());
    auto payload = BuildV1IssuerReg(aid, 0x0003u, assets::SPK_DEFAULT_ALLOWED);
    payload[38] = assets::ISSUER_REG_FORMAT_V2; // flip version, do NOT append delegate
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    BOOST_CHECK(!assets::ParseIssuerReg(tlv).has_value());
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_with_families)
{
    uint256 aid; memset(aid.data(), 0x33, aid.size());
    auto payload = BuildV1IssuerReg(
        aid,
        0x0003u, // policy_bits
        assets::SPK_P2PKH | assets::SPK_P2WPKH, // allowed_spk_families
        "", // no ticker
        0xFF, // no decimals
        std::numeric_limits<uint64_t>::max() // no unlock_fees
    );
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    auto reg = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(reg.has_value());
    BOOST_CHECK_EQUAL(reg->policy_bits, 0x0003u);
    BOOST_CHECK_EQUAL(reg->allowed_spk_families, (uint16_t)(assets::SPK_P2PKH | assets::SPK_P2WPKH));
    BOOST_CHECK_EQUAL(reg->format_version, assets::ISSUER_REG_FORMAT_V1);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v1_with_unlock)
{
    uint256 aid; memset(aid.data(), 0x44, aid.size());
    auto payload = BuildV1IssuerReg(
        aid,
        0x0003u, // policy_bits
        assets::SPK_P2WPKH | assets::SPK_P2TR,
        "", // no ticker
        0xFF, // no decimals
        500000 // unlock_fees_sats
    );
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    auto reg = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(reg.has_value());
    BOOST_CHECK_EQUAL(reg->unlock_fees_sats, (uint64_t)500000);
    BOOST_CHECK_EQUAL(reg->format_version, assets::ISSUER_REG_FORMAT_V1);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v1_with_ticker_decimals)
{
    uint256 aid; memset(aid.data(), 0x55, aid.size());
    auto payload = BuildV1IssuerReg(
        aid,
        0x0003u,
        assets::SPK_P2WPKH | assets::SPK_P2TR,
        "ABC", // ticker
        8, // decimals
        42 // unlock_fees
    );
    auto tlv = TLV(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG), payload);
    auto reg = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(reg.has_value());
    BOOST_CHECK_EQUAL(reg->ticker, std::string("ABC"));
    BOOST_CHECK_EQUAL(reg->decimals, 8);
    BOOST_CHECK_EQUAL(reg->unlock_fees_sats, (uint64_t)42);
    BOOST_CHECK_EQUAL(reg->format_version, assets::ISSUER_REG_FORMAT_V1);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v1_bad_ticker_lengths)
{
    uint256 aid; memset(aid.data(), 0x66, aid.size());

    // tlen=2 too short (min is 3)
    auto payload_short = BuildV1IssuerReg(aid, 0x0001u, assets::SPK_DEFAULT_ALLOWED, "AB");
    auto tlv_short = TLV((uint8_t)assets::OutExtType::ISSUER_REG, payload_short);
    BOOST_CHECK(!assets::ParseIssuerReg(tlv_short).has_value());

    // tlen=12 too long (max is 11)
    auto payload_long = BuildV1IssuerReg(aid, 0x0001u, assets::SPK_DEFAULT_ALLOWED, "ABCDEFGHIJKL");
    auto tlv_long = TLV((uint8_t)assets::OutExtType::ISSUER_REG, payload_long);
    BOOST_CHECK(!assets::ParseIssuerReg(tlv_long).has_value());
}

BOOST_AUTO_TEST_CASE(parse_unknown_tlv_type)
{
    std::vector<unsigned char> payload(4, 0xAA);
    auto tlv = TLV(0x99, payload);
    BOOST_CHECK(!assets::ParseAssetTag(tlv).has_value());
    BOOST_CHECK(!assets::ParseIssuerReg(tlv).has_value());
}

// --- Sponsored child ticker grammar (ICU_CHILD.md §3.1, §5.1) ---

BOOST_AUTO_TEST_CASE(ticker_grammar_helpers)
{
    using namespace assets;

    // Roots: 3..11 bytes, uppercase, first char a letter, alnum, no dot.
    BOOST_CHECK(IsRootTicker("ABC"));
    BOOST_CHECK(IsRootTicker("ACME"));
    BOOST_CHECK(IsRootTicker("A1B2C3"));
    BOOST_CHECK(IsRootTicker("ABCDEFGHIJK"));    // 11
    BOOST_CHECK(!IsRootTicker("AB"));            // too short
    BOOST_CHECK(!IsRootTicker("ABCDEFGHIJKL"));  // 12, too long
    BOOST_CHECK(!IsRootTicker("1ABC"));          // first char not a letter
    BOOST_CHECK(!IsRootTicker("abc"));           // lowercase
    BOOST_CHECK(!IsRootTicker("AB-C"));          // bad char
    BOOST_CHECK(!IsRootTicker("AC.ME"));         // dot is not a root char
    BOOST_CHECK(!IsRootTicker(""));

    // Children: exactly one dot, both sides valid roots.
    {
        auto c = ParseChildTicker("ACME.C150K");
        BOOST_REQUIRE(c.has_value());
        BOOST_CHECK_EQUAL(c->root, std::string("ACME"));
        BOOST_CHECK_EQUAL(c->suffix, std::string("C150K"));
    }
    BOOST_CHECK(ParseChildTicker("ABC.DEF").has_value());
    BOOST_CHECK(!ParseChildTicker("ACME").has_value());         // no dot
    BOOST_CHECK(!ParseChildTicker("ACME.").has_value());        // empty suffix
    BOOST_CHECK(!ParseChildTicker(".C150K").has_value());       // empty root
    BOOST_CHECK(!ParseChildTicker("A.BCD").has_value());        // root too short
    BOOST_CHECK(!ParseChildTicker("ACME.C1").has_value());      // suffix too short (deliberate)
    BOOST_CHECK(!ParseChildTicker("ACME.C150K.X").has_value()); // second dot
    BOOST_CHECK(!ParseChildTicker("ACME..C150").has_value());   // double dot
    BOOST_CHECK(!ParseChildTicker("acme.c150k").has_value());   // lowercase
    BOOST_CHECK(!ParseChildTicker("ACME.c150k").has_value());   // lowercase suffix

    // Combined gate: root OR one-hop child; empty rejected; dotless>11 rejected.
    BOOST_CHECK(IsTickerValidForIssuerReg("ACME"));
    BOOST_CHECK(IsTickerValidForIssuerReg("ACME.C150K"));
    BOOST_CHECK(!IsTickerValidForIssuerReg(""));
    BOOST_CHECK(!IsTickerValidForIssuerReg("ABCDEFGHIJKL")); // 12-byte dotless
    BOOST_CHECK(!IsTickerValidForIssuerReg("ACME.C150K.X")); // deeper
    BOOST_CHECK(!IsTickerValidForIssuerReg("ACME.C1"));      // short suffix
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v1_child_ticker)
{
    uint256 aid; memset(aid.data(), 0x77, aid.size());

    // A 10-byte child ticker round-trips through the consensus parser.
    auto payload = BuildV1IssuerReg(aid, 0x0001u, assets::SPK_DEFAULT_ALLOWED, "ACME.C150K");
    auto tlv = TLV((uint8_t)assets::OutExtType::ISSUER_REG, payload);
    auto reg = assets::ParseIssuerReg(tlv);
    BOOST_REQUIRE(reg.has_value());
    BOOST_CHECK_EQUAL(reg->ticker, std::string("ACME.C150K"));

    // Max-length child ticker: 11 + 1 + 11 = 23 bytes.
    auto payload_max = BuildV1IssuerReg(aid, 0x0001u, assets::SPK_DEFAULT_ALLOWED, "ABCDEFGHIJK.LMNOPQRSTUV");
    auto tlv_max = TLV((uint8_t)assets::OutExtType::ISSUER_REG, payload_max);
    auto reg_max = assets::ParseIssuerReg(tlv_max);
    BOOST_REQUIRE(reg_max.has_value());
    BOOST_CHECK_EQUAL(reg_max->ticker.size(), (size_t)23);
}

BOOST_AUTO_TEST_CASE(parse_issuer_reg_v1_rejects_bad_child_tickers)
{
    uint256 aid; memset(aid.data(), 0x88, aid.size());
    auto reject = [&](const std::string& t) {
        auto payload = BuildV1IssuerReg(aid, 0x0001u, assets::SPK_DEFAULT_ALLOWED, t);
        auto tlv = TLV((uint8_t)assets::OutExtType::ISSUER_REG, payload);
        BOOST_CHECK_MESSAGE(!assets::ParseIssuerReg(tlv).has_value(), "parser should reject ticker: " + t);
    };
    reject("ACME.C150K.X"); // deeper than one hop / second dot
    reject("ACME.");        // empty suffix
    reject(".C150K");       // empty root
    reject("ACME.C1");      // suffix too short
    reject("acme.c150k");   // lowercase
    reject("ACME..C150");   // double dot
    reject("ABCDEFGHIJKL"); // 12-byte dotless name
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(wrapped_key_v1_roundtrip)
{
    namespace kw = wallet::keywrap;

    kw::WrappedKeyV1 fields;
    fields.version = 1;
    fields.suite_id = 1;
    std::iota(fields.sender_ephemeral.begin(), fields.sender_ephemeral.end(), 1);
    std::iota(fields.ciphertext.begin(), fields.ciphertext.end(), 100);
    std::iota(fields.tag.begin(), fields.tag.end(), 200);

    auto encoded = kw::EncodeWrappedKeyV1(fields);
    auto decoded = kw::DecodeWrappedKeyV1(encoded);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, fields.version);
    BOOST_CHECK_EQUAL(decoded->suite_id, fields.suite_id);
    BOOST_CHECK(std::equal(decoded->sender_ephemeral.begin(), decoded->sender_ephemeral.end(),
                           fields.sender_ephemeral.begin()));
    BOOST_CHECK(std::equal(decoded->ciphertext.begin(), decoded->ciphertext.end(),
                           fields.ciphertext.begin()));
    BOOST_CHECK(std::equal(decoded->tag.begin(), decoded->tag.end(),
                           fields.tag.begin()));
}

BOOST_AUTO_TEST_CASE(taproot_extraction_positive_negative)
{
    namespace kw = wallet::keywrap;

    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xonly(key.GetPubKey());
    WitnessV1Taproot tap_dest{xonly};
    auto extracted = kw::ExtractTaprootPubkey(tap_dest);
    BOOST_REQUIRE(extracted.has_value());
    BOOST_CHECK(*extracted == xonly);

    // Non-taproot destinations must fail
    PKHash pkhash(key.GetPubKey().GetID());
    CTxDestination legacy_dest{pkhash};
    BOOST_CHECK(!kw::ExtractTaprootPubkey(legacy_dest).has_value());
}

BOOST_AUTO_TEST_CASE(keywrap_ecdh_roundtrip)
{
    namespace kw = wallet::keywrap;

    CKey sender_ephemeral;
    sender_ephemeral.MakeNewKey(true);
    CKey recipient_priv;
    recipient_priv.MakeNewKey(true);
    XOnlyPubKey recipient_xonly(recipient_priv.GetPubKey());

    WitnessV1Taproot tap_dest{recipient_xonly};
    CScript spk = GetScriptForDestination(tap_dest);
    uint256 spk_hash = kw::TapMatchHash(spk);

    std::array<unsigned char, 16> salt{};
    salt.fill(0x11);
    uint256 asset_id;
    std::fill(asset_id.begin(), asset_id.end(), 0);
    asset_id.begin()[0] = 1;
    uint256 ctxt_hash;
    std::fill(ctxt_hash.begin(), ctxt_hash.end(), 0);
    ctxt_hash.begin()[0] = 2;

    std::array<unsigned char, 32> dek{};
    GetRandBytes(dek);

    auto shared_secret_sender = kw::DeriveECDHSecret(sender_ephemeral, recipient_xonly);
    auto wrap_key = kw::DeriveWrapKey(shared_secret_sender, salt, asset_id, ctxt_hash, spk_hash);
    auto nonce = kw::NonceFromTapMatch(spk_hash);
    auto aad = kw::BuildAad(asset_id, ctxt_hash);
    auto ciphertext_with_tag = kw::EncryptDek(kw::KEYWRAP_SUITE_CHACHA20, dek, wrap_key, nonce, aad);
    BOOST_CHECK_EQUAL(ciphertext_with_tag.size(), 48);

    kw::WrappedKeyV1 blob;
    blob.version = 1;
    blob.suite_id = kw::KEYWRAP_SUITE_CHACHA20;
    XOnlyPubKey sender_xonly(sender_ephemeral.GetPubKey());
    std::copy_n(sender_xonly.begin(), blob.sender_ephemeral.size(), blob.sender_ephemeral.begin());
    std::copy_n(ciphertext_with_tag.begin(), blob.ciphertext.size(), blob.ciphertext.begin());
    std::copy_n(ciphertext_with_tag.end() - blob.tag.size(), blob.tag.size(), blob.tag.begin());

    auto shared_secret_receiver = kw::DeriveECDHSecret(recipient_priv, sender_xonly);
    auto wrap_key_receiver = kw::DeriveWrapKey(shared_secret_receiver, salt, asset_id, ctxt_hash, spk_hash);
    auto recovered = kw::DecryptDek(blob.suite_id, ciphertext_with_tag, wrap_key_receiver, nonce, aad);
    BOOST_CHECK_EQUAL_COLLECTIONS(dek.begin(), dek.end(), recovered.begin(), recovered.end());

    // Determinism check
    auto wrap_key_repeat = kw::DeriveWrapKey(shared_secret_sender, salt, asset_id, ctxt_hash, spk_hash);
    BOOST_CHECK_EQUAL_COLLECTIONS(wrap_key.begin(), wrap_key.end(), wrap_key_repeat.begin(), wrap_key_repeat.end());
}

BOOST_AUTO_TEST_CASE(keywrap_aead_tamper_detection)
{
    namespace kw = wallet::keywrap;

    CKey sender_ephemeral;
    sender_ephemeral.MakeNewKey(true);
    CKey recipient_priv;
    recipient_priv.MakeNewKey(true);
    XOnlyPubKey recipient_xonly(recipient_priv.GetPubKey());
    WitnessV1Taproot tap_dest{recipient_xonly};
    CScript spk = GetScriptForDestination(tap_dest);
    uint256 spk_hash = kw::TapMatchHash(spk);

    std::array<unsigned char, 16> salt{};
    salt.fill(0x22);
    uint256 asset_id;
    std::fill(asset_id.begin(), asset_id.end(), 0);
    asset_id.begin()[0] = 3;
    uint256 ctxt_hash;
    std::fill(ctxt_hash.begin(), ctxt_hash.end(), 0);
    ctxt_hash.begin()[0] = 4;

    std::array<unsigned char, 32> dek{};
    GetRandBytes(dek);

    auto shared_secret = kw::DeriveECDHSecret(sender_ephemeral, recipient_xonly);
    auto wrap_key = kw::DeriveWrapKey(shared_secret, salt, asset_id, ctxt_hash, spk_hash);
    auto nonce = kw::NonceFromTapMatch(spk_hash);
    auto aad = kw::BuildAad(asset_id, ctxt_hash);
    auto ciphertext_with_tag = kw::EncryptDek(kw::KEYWRAP_SUITE_CHACHA20, dek, wrap_key, nonce, aad);
    BOOST_REQUIRE_EQUAL(ciphertext_with_tag.size(), 48);

    // Tamper with tag
    ciphertext_with_tag.back() ^= 0xFF;
    auto sender_xonly = XOnlyPubKey(sender_ephemeral.GetPubKey());
    auto wrap_key_receiver = kw::DeriveWrapKey(kw::DeriveECDHSecret(recipient_priv, sender_xonly), salt, asset_id, ctxt_hash, spk_hash);
    BOOST_CHECK_THROW(kw::DecryptDek(kw::KEYWRAP_SUITE_CHACHA20, ciphertext_with_tag, wrap_key_receiver, nonce, aad), std::runtime_error);
}
#endif

// --- ISSUER_SCALAR TLV codec (CFD_GENERALISATION.md §3.1, Slice 1a) ---

BOOST_AUTO_TEST_CASE(issuer_scalar_tlv_roundtrip)
{
    assets::IssuerScalar s{};
    s.underlying_asset_id = uint256::FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").value();
    s.feed_id          = 0x01020304u;
    s.scalar_epoch     = 0x1122334455667788ull;
    s.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    s.scalar           = uint256::FromHex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100").value();

    const std::vector<unsigned char> tlv = assets::BuildIssuerScalarTlv(s);

    // Well-framed single TLV of the exact fixed width.
    BOOST_CHECK(ValidateSingleTLV(tlv));
    BOOST_CHECK_EQUAL(tlv.size(), 2u + assets::ISSUER_SCALAR_BODY_SIZE); // type + 1-byte len + body
    BOOST_CHECK_EQUAL(tlv[0], static_cast<uint8_t>(assets::OutExtType::ISSUER_SCALAR));
    BOOST_CHECK_EQUAL(tlv[1], assets::ISSUER_SCALAR_BODY_SIZE); // 78 < 253 -> 1-byte CompactSize

    auto parsed = assets::ParseIssuerScalar(tlv);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->underlying_asset_id == s.underlying_asset_id);
    BOOST_CHECK_EQUAL(parsed->feed_id, s.feed_id);
    BOOST_CHECK_EQUAL(parsed->scalar_epoch, s.scalar_epoch);
    BOOST_CHECK_EQUAL(parsed->scalar_format_id, s.scalar_format_id);
    BOOST_CHECK(parsed->scalar == s.scalar);
}

// Golden wire vector: pin EXACT offsets and endian bytes, independent of the
// builder, so a builder/parser pair that shares the same offset or endian mistake
// (which a round-trip alone cannot detect) is caught.
BOOST_AUTO_TEST_CASE(issuer_scalar_tlv_golden_wire)
{
    assets::IssuerScalar s{};
    s.underlying_asset_id = uint256::FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").value();
    s.feed_id          = 0x01020304u;
    s.scalar_epoch     = 0x1122334455667788ull;
    s.scalar_format_id = 0x0001u;
    s.scalar           = uint256::FromHex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100").value();

    const std::vector<unsigned char> t = assets::BuildIssuerScalarTlv(s);
    BOOST_REQUIRE_EQUAL(t.size(), 80u); // 1 type + 1 len + 78 body

    // Header.
    BOOST_CHECK_EQUAL(t[0], 0x11); // OutExtType::ISSUER_SCALAR
    BOOST_CHECK_EQUAL(t[1], 0x4e); // body length 78, canonical 1-byte CompactSize

    // underlying_asset_id at body offset 0 (wire [2..34)). uint256 stores the hex
    // big-endian string in reversed (LE) byte order, so the FIRST raw byte is the
    // LAST hex pair: 0xff. This pins the uint256 raw layout, not just the offset.
    BOOST_CHECK_EQUAL(t[2], 0xff);
    BOOST_CHECK(std::equal(s.underlying_asset_id.begin(), s.underlying_asset_id.end(), t.begin() + 2));

    // feed_id LE32 at body offset 32 (wire [34..38)).
    BOOST_CHECK_EQUAL(t[34], 0x04); BOOST_CHECK_EQUAL(t[35], 0x03);
    BOOST_CHECK_EQUAL(t[36], 0x02); BOOST_CHECK_EQUAL(t[37], 0x01);

    // scalar_epoch LE64 at body offset 36 (wire [38..46)).
    const std::array<unsigned char, 8> exp_epoch{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    BOOST_CHECK(std::equal(exp_epoch.begin(), exp_epoch.end(), t.begin() + 38));

    // scalar_format_id LE16 at body offset 44 (wire [46..48)).
    BOOST_CHECK_EQUAL(t[46], 0x01); BOOST_CHECK_EQUAL(t[47], 0x00);

    // scalar at body offset 46 (wire [48..80)); first raw byte is the last hex pair: 0x00.
    BOOST_CHECK_EQUAL(t[48], 0x00);
    BOOST_CHECK(std::equal(s.scalar.begin(), s.scalar.end(), t.begin() + 48));
}

BOOST_AUTO_TEST_CASE(issuer_scalar_tlv_rejects_malformed)
{
    assets::IssuerScalar s{};
    s.underlying_asset_id = uint256::FromHex(std::string(64, 'a')).value();
    s.feed_id = 7; s.scalar_epoch = 9; s.scalar_format_id = assets::SCALAR_FORMAT_RAW_U256_LE;
    s.scalar = uint256::FromHex(std::string(64, 'b')).value();
    const std::vector<unsigned char> good = assets::BuildIssuerScalarTlv(s);
    BOOST_REQUIRE(assets::ParseIssuerScalar(good).has_value());

    // Wrong type byte -> not an ISSUER_SCALAR.
    {
        auto bad = good; bad[0] = static_cast<uint8_t>(assets::OutExtType::ISSUER_REG);
        BOOST_CHECK(!assets::ParseIssuerScalar(bad).has_value());
    }
    // Short body (drop the last scalar byte; fix length) -> strict fixed-width reject.
    {
        std::vector<unsigned char> body(good.begin() + 2, good.end() - 1);
        std::vector<unsigned char> bad; bad.push_back(good[0]);
        bad.push_back(static_cast<uint8_t>(body.size()));
        bad.insert(bad.end(), body.begin(), body.end());
        BOOST_CHECK(ValidateSingleTLV(bad));               // still well-framed...
        BOOST_CHECK(!assets::ParseIssuerScalar(bad).has_value()); // ...but wrong width
    }
    // Trailing byte (extend body by one; fix length) -> strict fixed-width reject.
    {
        std::vector<unsigned char> body(good.begin() + 2, good.end());
        body.push_back(0x00);
        std::vector<unsigned char> bad; bad.push_back(good[0]);
        bad.push_back(static_cast<uint8_t>(body.size()));
        bad.insert(bad.end(), body.begin(), body.end());
        BOOST_CHECK(ValidateSingleTLV(bad));
        BOOST_CHECK(!assets::ParseIssuerScalar(bad).has_value());
    }
    // Non-canonical CompactSize: encode the 78-byte length as a 3-byte 0xfd form.
    // Both ValidateSingleTLV and the parser must reject (consensus never sees a
    // non-canonical frame because tx deserialize runs ValidateSingleTLV first).
    {
        std::vector<unsigned char> body(good.begin() + 2, good.end());
        std::vector<unsigned char> bad; bad.push_back(good[0]);
        bad.push_back(253);                                   // 0xfd
        bad.push_back(static_cast<unsigned char>(body.size() & 0xFF));
        bad.push_back(static_cast<unsigned char>((body.size() >> 8) & 0xFF));
        bad.insert(bad.end(), body.begin(), body.end());
        BOOST_CHECK(!ValidateSingleTLV(bad));
        BOOST_CHECK(!assets::ParseIssuerScalar(bad).has_value());
    }
    // Valid first TLV with an appended second TLV -> rejected (single-TLV container).
    {
        auto bad = good;
        const auto second = assets::BuildAssetTagTlv(uint256::FromHex(std::string(64, 'c')).value(), 1);
        bad.insert(bad.end(), second.begin(), second.end());
        BOOST_CHECK(!ValidateSingleTLV(bad));
        BOOST_CHECK(!assets::ParseIssuerScalar(bad).has_value());
    }

    // Format catalogue (Slice 6): RAW_U256_LE/BE + canonical U64/U128 (LE/BE). The decode/canonicality
    // behaviour of each is covered in scalar_cfd_payout_tests; here we just confirm membership.
    BOOST_CHECK(assets::IsKnownScalarFormat(assets::SCALAR_FORMAT_RAW_U256_LE));
    BOOST_CHECK(assets::IsKnownScalarFormat(assets::SCALAR_FORMAT_RAW_U256_BE));
    BOOST_CHECK(assets::IsKnownScalarFormat(assets::SCALAR_FORMAT_U64_LE));
    BOOST_CHECK(assets::IsKnownScalarFormat(assets::SCALAR_FORMAT_U128_BE));
    BOOST_CHECK(!assets::IsKnownScalarFormat(0x0000));
    BOOST_CHECK(!assets::IsKnownScalarFormat(0xFFFF));
}

// Pure scalar-publication rule check (CFD_GENERALISATION.md §3.3, Slice 1d). Each
// failure mode + deterministic first-failure-wins ordering + monotonic/immutable.
BOOST_AUTO_TEST_CASE(check_scalar_publication_rules)
{
    using assets::CheckScalarPublication;
    using S = assets::ScalarPubStatus;
    const uint16_t FMT = assets::SCALAR_FORMAT_RAW_U256_LE;
    const uint256 V{};                       // canonical under every format (0 decodes for all)
    uint256 nc{}; nc.begin()[8] = 1;         // bit 64 set -> NON-canonical for U64_*, canonical for RAW/U128
    const uint16_t U64 = assets::SCALAR_FORMAT_U64_LE;

    // Happy paths: first publication (no head) must be epoch 1; next epoch after a head.
    BOOST_CHECK(CheckScalarPublication(FMT, V, 1, /*carrier_unspendable=*/true, /*registered=*/true,
        /*icu_auth=*/true, /*head_exists=*/false, /*head_last=*/0, /*epoch_exists=*/false) == S::Ok);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 6, true, true, true, /*head_exists=*/true, 5, false) == S::Ok);

    // Each failure mode in isolation.
    BOOST_CHECK(CheckScalarPublication(0x0000, V, 1, true, true, true, false, 0, false) == S::BadFormat);
    BOOST_CHECK(CheckScalarPublication(U64, nc, 1, true, true, true, false, 0, false) == S::NonCanonical); // overflows u64
    BOOST_CHECK(CheckScalarPublication(FMT, V, 1, /*unspendable=*/false, true, true, false, 0, false) == S::CarrierSpendable);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 1, true, /*registered=*/false, true, false, 0, false) == S::UnknownAsset);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 1, true, true, /*icu_auth=*/false, false, 0, false) == S::NoIcuAuth);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 0, true, true, true, false, 0, false) == S::ZeroEpoch);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 1, true, true, true, /*head_exists=*/true,
        std::numeric_limits<uint64_t>::max(), false) == S::EpochOverflow);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 7, true, true, true, true, 5, false) == S::NonMonotonic); // gap
    BOOST_CHECK(CheckScalarPublication(FMT, V, 5, true, true, true, true, 5, false) == S::NonMonotonic); // stale/replay
    BOOST_CHECK(CheckScalarPublication(FMT, V, 2, true, true, true, false, 0, false) == S::NonMonotonic); // first must be 1
    BOOST_CHECK(CheckScalarPublication(FMT, V, 6, true, true, true, true, 5, /*epoch_exists=*/true) == S::DuplicateEpoch);
    // The same non-canonical value IS accepted under a wider format (RAW/U128 have room for bit 64).
    BOOST_CHECK(CheckScalarPublication(FMT, nc, 1, true, true, true, false, 0, false) == S::Ok);

    // Deterministic ordering: BadFormat precedes canonicality; canonicality precedes carrier/registration.
    BOOST_CHECK(CheckScalarPublication(0x0000, nc, 0, false, false, false, false, 0, false) == S::BadFormat);
    BOOST_CHECK(CheckScalarPublication(U64, nc, 0, /*unspendable=*/false, false, false, false, 0, false) == S::NonCanonical);
    BOOST_CHECK(CheckScalarPublication(FMT, V, 0, false, false, false, false, 0, false) == S::CarrierSpendable);

    // Reject-reason tokens are stable (consensus-visible strings).
    BOOST_CHECK_EQUAL(std::string(assets::ScalarPubStatusString(S::Ok)), "scalar-ok");
    BOOST_CHECK_EQUAL(std::string(assets::ScalarPubStatusString(S::NonMonotonic)), "scalar-nonmonotonic");
    BOOST_CHECK_EQUAL(std::string(assets::ScalarPubStatusString(S::NoIcuAuth)), "scalar-no-icu-auth");
    BOOST_CHECK_EQUAL(std::string(assets::ScalarPubStatusString(S::CarrierSpendable)), "scalar-carrier-spendable");
    BOOST_CHECK_EQUAL(std::string(assets::ScalarPubStatusString(S::DuplicateEpoch)), "scalar-duplicate-epoch");
}

// Scalar-fixing burial predicate (CFD_GENERALISATION.md §3.4, Slice 2).
BOOST_AUTO_TEST_CASE(scalar_fixing_buried)
{
    BOOST_CHECK(ScalarCfdFixingBuried(/*pub=*/90, /*ctx=*/110, /*mat=*/10));   // 90 <= 100, 90 < 110
    BOOST_CHECK(ScalarCfdFixingBuried(100, 110, 10));                          // boundary: 100 <= 100
    BOOST_CHECK(!ScalarCfdFixingBuried(101, 110, 10));                         // 101 > 110-10
    BOOST_CHECK(!ScalarCfdFixingBuried(110, 110, 10));                         // not < ctx
    BOOST_CHECK(!ScalarCfdFixingBuried(-1, 110, 10));                          // negative pub height
}

// Deterministic three-way deadline/fallback resolution (CFD_GENERALISATION.md §3.4, Slice 2).
BOOST_AUTO_TEST_CASE(scalar_fixing_resolution)
{
    const uint256 U = uint256::FromHex(std::string(64, 'a')).value();
    const uint256 FB = uint256::FromHex(std::string(64, 'f')).value();
    const uint256 REAL = uint256::FromHex(std::string(64, '1')).value();
    const uint32_t feed = 3;
    const uint64_t epoch = 5;
    const int MAT = 10, GRACE = 10, DEADLINE = 100;  // GRACE >= MAT (the consensus invariant)
    const uint16_t LEAF_FMT = assets::SCALAR_FORMAT_RAW_U256_LE;

    // reader that returns a record for the target (U, feed, epoch) published at pub_h, else nullopt.
    auto reader_pub = [&](int pub_h, uint16_t fmt) {
        return std::function<std::optional<ScalarRecord>(const uint256&, uint32_t, uint64_t)>(
            [=](const uint256& a, uint32_t f, uint64_t e) -> std::optional<ScalarRecord> {
                if (a == U && f == feed && e == epoch) {
                    ScalarRecord r; r.scalar = REAL; r.publication_height = pub_h; r.scalar_format_id = fmt;
                    return r;
                }
                return std::nullopt;
            });
    };
    auto reader_none = std::function<std::optional<ScalarRecord>(const uint256&, uint32_t, uint64_t)>(
        [](const uint256&, uint32_t, uint64_t) -> std::optional<ScalarRecord> { return std::nullopt; });

    auto resolve = [&](int ctx, const auto& reader) {
        return ResolveScalarFixing(U, feed, epoch, DEADLINE, FB, LEAF_FMT, ctx, MAT, GRACE, reader);
    };

    // A) real in-time (pub 95 <= deadline), buried (ctx 110), matching format -> real
    {
        auto r = resolve(110, reader_pub(95, LEAF_FMT));
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(!r->is_fallback);
        BOOST_CHECK(r->scalar == REAL);
        BOOST_CHECK_EQUAL(r->scalar_format_id, LEAF_FMT);
    }
    // B) real in-time (pub 100) but NOT yet buried (ctx 105) and before deadline+grace: pending
    BOOST_CHECK(!resolve(105, reader_pub(100, LEAF_FMT)).has_value());
    // C) race-freedom: at ctx == deadline+grace (110), an in-time fixing (pub 100) is already
    //    buried, so branch 1 wins -> real, NEVER the fallback.
    {
        auto r = resolve(110, reader_pub(100, LEAF_FMT));
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(!r->is_fallback);
        BOOST_CHECK(r->scalar == REAL);
    }
    // D) real published LATE (pub 101 > deadline) is IGNORED; past grace -> fallback (leaf format)
    {
        auto r = resolve(120, reader_pub(101, LEAF_FMT));
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(r->is_fallback);
        BOOST_CHECK(r->scalar == FB);
        BOOST_CHECK_EQUAL(r->scalar_format_id, LEAF_FMT);
    }
    // E) no real fixing, past deadline+grace -> fallback
    {
        auto r = resolve(120, reader_none);
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(r->is_fallback);
        BOOST_CHECK(r->scalar == FB);
    }
    // F) no real fixing, before deadline+grace -> pending
    BOOST_CHECK(!resolve(105, reader_none).has_value());
    // G) real in-time and buried BEFORE the grace window (pub 80, ctx 95): real usable immediately
    {
        auto r = resolve(95, reader_pub(80, LEAF_FMT));
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(!r->is_fallback);
        BOOST_CHECK(r->scalar == REAL);
    }
    // H) format MISMATCH: a real fixing in a different encoding is UNUSABLE (like a missing one).
    //    H1: past grace -> fallback; H2: before grace -> pending. Never returns the mismatched real.
    {
        auto r = resolve(120, reader_pub(95, /*fmt=*/7));  // 7 != LEAF_FMT
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(r->is_fallback);
        BOOST_CHECK(r->scalar == FB);
        BOOST_CHECK_EQUAL(r->scalar_format_id, LEAF_FMT);
    }
    BOOST_CHECK(!resolve(105, reader_pub(95, /*fmt=*/7)).has_value());

    // I) grace < maturity (mis-configured param) is CLAMPED to maturity: an in-time fixing that
    //    is not yet buried must NOT fall to fallback. grace=5, maturity=10, deadline=100.
    //    ctx 106 (>= deadline+grace=105 but < deadline+maturity=110): pending, not fallback.
    {
        auto r = ResolveScalarFixing(U, feed, epoch, DEADLINE, FB, LEAF_FMT, /*ctx=*/106,
                                     /*maturity=*/10, /*grace=*/5, reader_pub(100, LEAF_FMT));
        BOOST_CHECK(!r.has_value());  // clamp prevents premature fallback (race-freedom preserved)
    }
    {
        auto r = ResolveScalarFixing(U, feed, epoch, DEADLINE, FB, LEAF_FMT, /*ctx=*/110,
                                     /*maturity=*/10, /*grace=*/5, reader_pub(100, LEAF_FMT));
        BOOST_REQUIRE(r.has_value());  // now buried -> real
        BOOST_CHECK(!r->is_fallback);
        BOOST_CHECK(r->scalar == REAL);
    }

    // J) overflow-safety: a near-UINT32_MAX deadline must not overflow deadline+grace. With no
    //    usable real fixing and a small context the result is "pending" (never fallback), no UB;
    //    and a buried in-time real fixing still resolves under a huge deadline.
    {
        const uint32_t huge = std::numeric_limits<uint32_t>::max();
        BOOST_CHECK(!ResolveScalarFixing(U, feed, epoch, huge, FB, LEAF_FMT, /*ctx=*/110, MAT, GRACE, reader_none).has_value());
        auto r = ResolveScalarFixing(U, feed, epoch, huge, FB, LEAF_FMT, /*ctx=*/110, MAT, GRACE, reader_pub(95, LEAF_FMT));
        BOOST_REQUIRE(r.has_value());
        BOOST_CHECK(!r->is_fallback);
        BOOST_CHECK(r->scalar == REAL);
    }
}

// ---- Slice 4b: COLLATERAL_SAFE is DELIBERATELY EXCLUDED from the core policy commit ----------
// (CFD_GENERALISATION.md §5.1). Folding 0x40 into core_policy_commit would be unconditional —
// changing registry state the instant the binary ships, before ScalarCfdHeight — so a future
// pre-activation 0x40 registration would diverge upgraded vs un-upgraded nodes. Instead 0x40 is an
// ordinary ignored policy bit at the commit layer, and its immutability is a separate height-gated
// rule (collateral_safe_rotation_rule below). This test pins the no-retroactivity guarantee.
BOOST_AUTO_TEST_CASE(core_policy_commit_excludes_collateral_safe)
{
    using namespace assets;
    const uint16_t fam = 0x0003;
    const uint32_t kyc = 0, tfr = 0;
    const uint32_t base_bits = MINT_ALLOWED | BURN_ALLOWED; // 0x03

    // Setting 0x40 must NOT change the commit -> an existing/future 0x40 asset has a byte-identical
    // commit on upgraded and un-upgraded nodes (no divergence ahead of the flag-day).
    const uint256 without = ComputeCorePolicyCommit(fam, base_bits, kyc, tfr);
    const uint256 with40  = ComputeCorePolicyCommit(fam, base_bits | COLLATERAL_SAFE, kyc, tfr);
    BOOST_CHECK(with40 == without);

    // The bit is 0x40 and is NOT in the immutable mask (so it never enters the commit).
    BOOST_CHECK_EQUAL(COLLATERAL_SAFE, 0x40u);
    BOOST_CHECK((POLICY_BITS_IMMUTABLE_MASK & COLLATERAL_SAFE) == 0u);

    // The genuinely-immutable bits still ARE in the commit (regression: mask not over-trimmed).
    BOOST_CHECK(ComputeCorePolicyCommit(fam, base_bits | KYC_REQUIRED, kyc, tfr) != without);
}

// ---- Slice 4b: the collateral-safe immutability rule (§5.1), height-gated --------------------
// Direct test of the pure rule ConnectBlock applies byte-identically. It freezes, post-activation,
// BOTH the COLLATERAL_SAFE bit itself (since it is no longer in core_policy_commit) AND icu_flags
// for an asset carrying it. The ConnectBlock wiring (Invalid+break, arg threading) gets its
// end-to-end proof in the 4d functional test, as the other rotation-governance rules are proven.
BOOST_AUTO_TEST_CASE(collateral_safe_rotation_rule)
{
    using namespace assets;
    constexpr int ACT = 1000;                          // a ScalarCfdHeight
    const uint32_t BASE = MINT_ALLOWED | BURN_ALLOWED; // 0x03
    const uint32_t SAFE = BASE | COLLATERAL_SAFE;      // 0x43

    // POSITIVE — bit toggled at/above activation is rejected, both directions.
    BOOST_CHECK(IsCollateralSafeRotationRejected(BASE, SAFE, 0, 0, ACT,      ACT)); // add the bit
    BOOST_CHECK(IsCollateralSafeRotationRejected(SAFE, BASE, 0, 0, ACT + 50, ACT)); // remove the bit

    // POSITIVE — icu_flags drift on a collateral-safe asset is rejected (either direction).
    BOOST_CHECK(IsCollateralSafeRotationRejected(SAFE, SAFE, 0, WRAP_REQUIRED, ACT,      ACT));
    BOOST_CHECK(IsCollateralSafeRotationRejected(SAFE, SAFE, WRAP_REQUIRED, 0, ACT + 50, ACT));
    BOOST_CHECK(IsCollateralSafeRotationRejected(SAFE, SAFE, 0, ICU_COMPRESSED, ACT,     ACT));

    // NEGATIVE 1 — below activation: fully inert (no consensus change pre-flag-day), even for the
    // exact rotations rejected above.
    BOOST_CHECK(!IsCollateralSafeRotationRejected(BASE, SAFE, 0, 0,            ACT - 1, ACT));
    BOOST_CHECK(!IsCollateralSafeRotationRejected(SAFE, SAFE, 0, WRAP_REQUIRED, ACT - 1, ACT));

    // NEGATIVE 2 — non-collateral-safe asset: bit absent both sides, icu_flags drift allowed.
    BOOST_CHECK(!IsCollateralSafeRotationRejected(BASE, BASE, 0, WRAP_REQUIRED, ACT + 50, ACT));

    // NEGATIVE 3 — collateral-safe, nothing protected changed: a benign rotation is allowed.
    BOOST_CHECK(!IsCollateralSafeRotationRejected(SAFE, SAFE, WRAP_REQUIRED, WRAP_REQUIRED, ACT + 50, ACT));
    BOOST_CHECK(!IsCollateralSafeRotationRejected(SAFE, SAFE, 0, 0, ACT + 50, ACT));
}

BOOST_AUTO_TEST_SUITE_END()
