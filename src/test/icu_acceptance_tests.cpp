// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/icu_acceptance.h>
#include <assets/icu_acceptance_record.h>

#include <crypto/sha256.h>
#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <set>
#include <string>
#include <vector>

using assets::BuildAcceptanceMessage;
using assets::IcuAcceptanceMode;
using assets::IcuAcceptanceModeName;

namespace {
uint256 H(char c) { return uint256::FromHex(std::string(64, c)).value(); }
} // namespace

BOOST_AUTO_TEST_SUITE(icu_acceptance_tests)

// The acceptance object is the canonical DOCUMENT hash (registry icu_plain_commit). The
// only derived artifact is the BIP-322 message a holder signs; these tests pin its shape.

BOOST_AUTO_TEST_CASE(message_is_deterministic)
{
    const uint256 asset = H('1');
    const uint256 canon = H('2');
    const std::string a = BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, asset, canon, "holderA");
    const std::string b = BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, asset, canon, "holderA");
    BOOST_CHECK_EQUAL(a, b);
}

BOOST_AUTO_TEST_CASE(message_changes_with_each_field)
{
    const uint256 asset = H('1');
    const uint256 canon = H('2');
    const std::string base = BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, asset, canon, "holderA");

    BOOST_CHECK_NE(base, BuildAcceptanceMessage(IcuAcceptanceMode::RETURN, asset, canon, "holderA"));
    BOOST_CHECK_NE(base, BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, H('3'), canon, "holderA"));
    BOOST_CHECK_NE(base, BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, asset, H('4'), "holderA"));
    BOOST_CHECK_NE(base, BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, asset, canon, "holderB"));
}

BOOST_AUTO_TEST_CASE(message_excludes_issuer_for_rotation_robustness)
{
    // The issuer is intentionally not in the message: asset_id pins it, and excluding it keeps an
    // acknowledgment verifiable across an issuer ICU address rotation.
    const std::string msg = BuildAcceptanceMessage(IcuAcceptanceMode::ACKNOWLEDGE, H('1'), H('2'), "holderA");
    BOOST_CHECK_EQUAL(std::count(msg.begin(), msg.end(), '|'), 4);  // tag|asset|mode|hash|holder
}

BOOST_AUTO_TEST_CASE(message_format_is_frozen)
{
    // Deterministic pipe-delimited string; pinned so the holder-signature reconstruction can't drift.
    const std::string ones(64, '1');
    const std::string twos(64, '2');
    const std::string msg = BuildAcceptanceMessage(
        IcuAcceptanceMode::ACKNOWLEDGE, H('1'), H('2'), "bcrt1qholder");
    BOOST_CHECK_EQUAL(msg,
        "TSC-ICU-DOC-ACCEPT-1|" + ones + "|acknowledge|" + twos + "|bcrt1qholder");
}

BOOST_AUTO_TEST_CASE(mode_names)
{
    BOOST_CHECK_EQUAL(std::string(IcuAcceptanceModeName(IcuAcceptanceMode::ACKNOWLEDGE)), "acknowledge");
    BOOST_CHECK_EQUAL(std::string(IcuAcceptanceModeName(IcuAcceptanceMode::RETURN)), "return");
}

// ---- On-chain acceptance record (0x40 vExt) -- consensus-free format + family-aware verify ----

BOOST_AUTO_TEST_CASE(record_serialize_parse_roundtrip)
{
    using assets::IcuAcceptanceRecord;
    using assets::IcuAcceptSigScheme;
    IcuAcceptanceRecord r;
    r.mode = static_cast<uint8_t>(IcuAcceptanceMode::ACKNOWLEDGE);
    r.asset_id = H('a');
    r.icu_plain_commit = H('b');
    r.holder_prevout_txid = H('c');
    r.holder_prevout_vout = 2;
    r.holder_spk_hash = H('d');
    r.accepted_units = 1234567890123ULL;
    r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW);
    std::array<unsigned char, 32> ref1{}; ref1.fill(0x11);
    std::array<unsigned char, 32> ref2{}; ref2.fill(0x22);
    r.body_refs = {ref1, ref2};
    r.sig = std::vector<unsigned char>(64, 0xAB);

    const auto parsed = IcuAcceptanceRecord::ParsePayload(r.SerializePayload());
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK_EQUAL(int(parsed->mode), int(r.mode));
    BOOST_CHECK(parsed->asset_id == r.asset_id);
    BOOST_CHECK(parsed->icu_plain_commit == r.icu_plain_commit);
    BOOST_CHECK(parsed->holder_prevout_txid == r.holder_prevout_txid);
    BOOST_CHECK_EQUAL(parsed->holder_prevout_vout, 2u);
    BOOST_CHECK(parsed->holder_spk_hash == r.holder_spk_hash);
    BOOST_CHECK_EQUAL(parsed->accepted_units, r.accepted_units);
    BOOST_CHECK_EQUAL(int(parsed->sig_scheme), int(r.sig_scheme));
    BOOST_REQUIRE_EQUAL(parsed->body_refs.size(), 2u);
    BOOST_CHECK(parsed->body_refs[0] == ref1);
    BOOST_CHECK(parsed->body_refs[1] == ref2);
    BOOST_CHECK(parsed->sig == r.sig);
}

BOOST_AUTO_TEST_CASE(record_tlv_wrap_unwrap)
{
    using assets::IcuAcceptanceRecord;
    IcuAcceptanceRecord r;
    r.asset_id = H('1'); r.icu_plain_commit = H('2'); r.holder_prevout_txid = H('3'); r.holder_spk_hash = H('4');
    r.accepted_units = 1;
    r.sig_scheme = static_cast<uint8_t>(assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW);
    r.sig = std::vector<unsigned char>(64, 7);  // a valid (semantically-complete) signed ACK so parse accepts it
    const auto tlv = assets::BuildIcuAcceptanceTLV(r);
    BOOST_REQUIRE(!tlv.empty());
    BOOST_CHECK_EQUAL(int(tlv[0]), int(assets::ICU_ACCEPTANCE_TLV_TYPE));  // 0x40
    BOOST_REQUIRE(assets::ParseIcuAcceptanceTLV(tlv).has_value());
    // Wrong type byte (TFR_ANCHOR 0x21) or trailing junk => rejected.
    auto wrong = tlv; wrong[0] = 0x21;
    BOOST_CHECK(!assets::ParseIcuAcceptanceTLV(wrong));
    auto trailer = tlv; trailer.push_back(0x00);
    BOOST_CHECK(!assets::ParseIcuAcceptanceTLV(trailer));
}

BOOST_AUTO_TEST_CASE(record_signing_message_binds_all_fields)
{
    using assets::IcuAcceptanceRecord;
    using assets::IcuAcceptSigScheme;
    auto base = []() {
        IcuAcceptanceRecord r;
        r.mode = static_cast<uint8_t>(IcuAcceptanceMode::ACKNOWLEDGE);
        r.asset_id = H('a'); r.icu_plain_commit = H('b');
        r.holder_prevout_txid = H('c'); r.holder_prevout_vout = 1;
        r.holder_spk_hash = H('d'); r.accepted_units = 100;
        r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW);
        std::array<unsigned char, 32> ref{}; ref.fill(0x33); r.body_refs = {ref};
        r.sig = std::vector<unsigned char>(64, 1);
        return r;
    };
    const std::string m0 = assets::IcuAcceptanceRecordSigningMessage(base());
    // The message must carry the binding fields the off-chain ACCEPT-3 message lacked.
    BOOST_CHECK(m0.find("TSC-ICU-ACCEPTANCE-RECORD-1") != std::string::npos);
    BOOST_CHECK(m0.find("prevout=") != std::string::npos);
    BOOST_CHECK(m0.find("units=100") != std::string::npos);
    BOOST_CHECK(m0.find("scheme=") != std::string::npos);

    auto msg = [](IcuAcceptanceRecord r) { return assets::IcuAcceptanceRecordSigningMessage(r); };
    // Changing ANY bound field changes the message...
    { auto r = base(); r.holder_prevout_vout = 2; BOOST_CHECK(msg(r) != m0); }
    { auto r = base(); r.accepted_units = 101; BOOST_CHECK(msg(r) != m0); }
    { auto r = base(); r.holder_prevout_txid = H('e'); BOOST_CHECK(msg(r) != m0); }
    { auto r = base(); r.holder_spk_hash = H('f'); BOOST_CHECK(msg(r) != m0); }
    { auto r = base(); r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_BIP322_HASH); r.sig.assign(32, 0); BOOST_CHECK(msg(r) != m0); }
    { auto r = base(); std::array<unsigned char, 32> x{}; x.fill(0x44); r.body_refs = {x}; BOOST_CHECK(msg(r) != m0); }
    // ...but the signature itself is excluded from the signed message.
    { auto r = base(); r.sig = std::vector<unsigned char>(64, 2); BOOST_CHECK_EQUAL(msg(r), m0); }
}

BOOST_AUTO_TEST_CASE(record_commit_reveal_check)
{
    using assets::IcuAcceptanceRecord;
    using assets::IcuAcceptSigScheme;
    const std::vector<unsigned char> proof(96, 0x5A);  // a stand-in BIP-322 proof
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(proof.data(), proof.size()).Finalize(digest);
    IcuAcceptanceRecord r;
    r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_BIP322_HASH);
    r.sig.assign(digest, digest + CSHA256::OUTPUT_SIZE);
    BOOST_CHECK(assets::VerifyIcuAcceptanceCommit(r, proof));                                       // matches
    BOOST_CHECK(!assets::VerifyIcuAcceptanceCommit(r, std::vector<unsigned char>(96, 0x5B)));       // wrong proof
    r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW);                           // wrong scheme
    BOOST_CHECK(!assets::VerifyIcuAcceptanceCommit(r, proof));
}

BOOST_AUTO_TEST_CASE(record_parse_rejects_malformed)
{
    using assets::IcuAcceptanceRecord;
    IcuAcceptanceRecord r; r.asset_id = H('1');
    const auto bytes = r.SerializePayload();
    BOOST_CHECK(!IcuAcceptanceRecord::ParsePayload(std::vector<unsigned char>(bytes.begin(), bytes.end() - 1)));  // truncated
    auto withTrailer = bytes; withTrailer.push_back(0x00);
    BOOST_CHECK(!IcuAcceptanceRecord::ParsePayload(withTrailer));                                                 // trailing byte
    auto wrongVer = bytes; wrongVer[0] = 0x99;
    BOOST_CHECK(!IcuAcceptanceRecord::ParsePayload(wrongVer));                                                    // bad version
    BOOST_CHECK(!IcuAcceptanceRecord::ParsePayload({}));                                                          // empty
}

BOOST_AUTO_TEST_CASE(record_semantic_validation_fail_closed)
{
    using assets::IcuAcceptanceRecord;
    using assets::IcuAcceptSigScheme;
    auto base = []() {
        IcuAcceptanceRecord r;
        r.mode = static_cast<uint8_t>(IcuAcceptanceMode::ACKNOWLEDGE);
        r.asset_id = H('a'); r.icu_plain_commit = H('b');
        r.holder_prevout_txid = H('c'); r.holder_spk_hash = H('d');
        r.accepted_units = 100;
        r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW);
        r.sig = std::vector<unsigned char>(64, 1);
        return r;
    };
    std::string why;
    BOOST_CHECK(assets::ValidateIcuAcceptanceRecord(base(), why));

    // ParsePayload must fail-closed on every semantic violation (so consensus rejects garbage 0x40).
    auto rejects = [](IcuAcceptanceRecord r) {
        return !IcuAcceptanceRecord::ParsePayload(r.SerializePayload()).has_value();
    };
    { auto r = base(); r.mode = 7; BOOST_CHECK(rejects(r)); }                          // bad mode
    { auto r = base(); r.flags = 1; BOOST_CHECK(rejects(r)); }                         // nonzero reserved flags
    { auto r = base(); r.sig_scheme = 9; BOOST_CHECK(rejects(r)); }                    // unknown scheme
    { auto r = base(); r.asset_id.SetNull(); BOOST_CHECK(rejects(r)); }                // null required hash
    { auto r = base(); r.accepted_units = 0; BOOST_CHECK(rejects(r)); }                // zero units
    { auto r = base(); r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_BIP322_HASH); r.sig.assign(31, 0); BOOST_CHECK(rejects(r)); } // wrong commitment len
    { auto r = base(); r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::NONE); BOOST_CHECK(rejects(r)); }  // NONE must carry no sig
    { auto r = base(); std::array<unsigned char, 32> a{}; a.fill(0x22); std::array<unsigned char, 32> b{}; b.fill(0x11); r.body_refs = {a, b}; BOOST_CHECK(rejects(r)); }  // unsorted
    { auto r = base(); std::array<unsigned char, 32> a{}; a.fill(0x11); r.body_refs = {a, a}; BOOST_CHECK(rejects(r)); }  // duplicate
    { auto r = base(); r.mode = static_cast<uint8_t>(IcuAcceptanceMode::RETURN); std::array<unsigned char, 32> a{}; a.fill(0x11); r.body_refs = {a}; BOOST_CHECK(rejects(r)); }  // return + refs
    { auto r = base(); r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::NONE); r.sig.clear(); BOOST_CHECK(rejects(r)); }  // ACK must be signed (mode/scheme coupling)
    { auto r = base(); r.mode = static_cast<uint8_t>(IcuAcceptanceMode::RETURN); BOOST_CHECK(rejects(r)); }                       // RETURN must not be signed
    { auto r = base(); r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW); r.sig.assign(63, 0); BOOST_CHECK(rejects(r)); }  // raw Schnorr wrong length

    // A valid raw-Schnorr (P2TR-v2) ACK round-trips.
    { auto r = base(); r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW); r.sig.assign(64, 9);
      BOOST_CHECK(IcuAcceptanceRecord::ParsePayload(r.SerializePayload()).has_value()); }

    // A valid RETURN (no refs, no signature) round-trips.
    { auto r = base(); r.mode = static_cast<uint8_t>(IcuAcceptanceMode::RETURN);
      r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::NONE); r.sig.clear(); r.body_refs.clear();
      BOOST_CHECK(IcuAcceptanceRecord::ParsePayload(r.SerializePayload()).has_value()); }
}

// SECP_SCHNORR_RAW sign+verify (the taproot create/verify primitive). Needs the ECC context, so this one
// case uses the BasicTestingSetup fixture. Signing here mirrors what the wallet create-path will do; the
// library's VerifyIcuAcceptanceRecordSchnorr is the read-layer verify.
BOOST_FIXTURE_TEST_CASE(record_schnorr_raw_sign_verify_binds_record, BasicTestingSetup)
{
    using assets::IcuAcceptanceRecord;
    using assets::IcuAcceptSigScheme;
    CKey key; key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey xonly(key.GetPubKey());

    IcuAcceptanceRecord r;
    r.mode = static_cast<uint8_t>(IcuAcceptanceMode::ACKNOWLEDGE);
    r.asset_id = H('a'); r.icu_plain_commit = H('b');
    r.holder_prevout_txid = H('c'); r.holder_prevout_vout = 1;
    r.holder_spk_hash = H('d'); r.accepted_units = 100;
    r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW);
    std::array<unsigned char, 32> ref{}; ref.fill(0x33); r.body_refs = {ref};

    std::vector<unsigned char> sig(64);
    BOOST_REQUIRE(key.SignSchnorr(assets::IcuAcceptanceRecordSigningHash(r), sig, /*merkle_root=*/nullptr, uint256{}));
    r.sig = sig;
    BOOST_CHECK(assets::VerifyIcuAcceptanceRecordSchnorr(r, xonly));   // valid sig over this record

    // The signature binds the record: tampering any bound field breaks verification.
    { auto t = r; t.accepted_units = 101;         BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(t, xonly)); }
    { auto t = r; t.holder_prevout_vout = 2;       BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(t, xonly)); }
    { auto t = r; t.holder_prevout_txid = H('e');  BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(t, xonly)); }
    { auto t = r; std::array<unsigned char, 32> x{}; x.fill(0x44); t.body_refs = {x}; BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(t, xonly)); }

    // Wrong key / wrong scheme / wrong length all fail.
    CKey other; other.MakeNewKey(true);
    BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(r, XOnlyPubKey(other.GetPubKey())));
    { auto t = r; t.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_BIP322_HASH); BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(t, xonly)); }
    { auto t = r; t.sig.pop_back(); BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(t, xonly)); }
}

// Mirror REAL P2TR key-path signing: sign with the TWEAKED output key, verify against the on-chain
// output key Q (what the verifier extracts from the prevout spk). The untweaked internal key must NOT
// verify -- this pins the exact signing recipe the create RPC must use (sign with the prevout's tweak).
BOOST_FIXTURE_TEST_CASE(record_schnorr_raw_verifies_against_tweaked_p2tr_output_key, BasicTestingSetup)
{
    using assets::IcuAcceptanceRecord;
    using assets::IcuAcceptSigScheme;
    CKey key; key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey internal(key.GetPubKey());
    const auto tweaked = internal.CreateTapTweak(/*merkle_root=*/nullptr);  // BIP86 key-path-only output key Q
    BOOST_REQUIRE(tweaked.has_value());
    const XOnlyPubKey output_key = tweaked->first;

    IcuAcceptanceRecord r;
    r.mode = static_cast<uint8_t>(IcuAcceptanceMode::ACKNOWLEDGE);
    r.asset_id = H('a'); r.icu_plain_commit = H('b');
    r.holder_prevout_txid = H('c'); r.holder_prevout_vout = 0;
    r.holder_spk_hash = H('d'); r.accepted_units = 7;
    r.sig_scheme = static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW);

    const uint256 merkle_root{};  // null => BIP86 key-path-only, matching CreateTapTweak(nullptr)
    std::vector<unsigned char> sig(64);
    BOOST_REQUIRE(key.SignSchnorr(assets::IcuAcceptanceRecordSigningHash(r), sig, &merkle_root, uint256{}));
    r.sig = sig;

    BOOST_CHECK(assets::VerifyIcuAcceptanceRecordSchnorr(r, output_key));   // verifies against Q (the on-chain key)
    BOOST_CHECK(!assets::VerifyIcuAcceptanceRecordSchnorr(r, internal));    // NOT against the untweaked internal key
}

// body_refs must be a subset of the committed context's designated clauses (and ALL of them when the
// context is 'required'); a no-context asset must carry no refs. This is the read-layer check that stops
// a record with a valid holder signature over BOGUS/incomplete refs from verifying.
BOOST_AUTO_TEST_CASE(body_refs_against_context)
{
    auto ref = [](unsigned char b) { std::array<unsigned char, 32> a{}; a.fill(b); return a; };
    const std::string A = HexStr(ref(0x11)), B = HexStr(ref(0x22));
    const std::set<std::string> designated{A, B};
    std::string why;

    // No context: empty refs OK; any refs rejected.
    BOOST_CHECK(assets::CheckIcuBodyRefsAgainstContext({}, /*has_context=*/false, {}, /*required=*/false, why));
    BOOST_CHECK(!assets::CheckIcuBodyRefsAgainstContext({ref(0x11)}, false, {}, false, why));

    // Optional context: any subset of designated is OK.
    BOOST_CHECK(assets::CheckIcuBodyRefsAgainstContext({}, true, designated, /*required=*/false, why));
    BOOST_CHECK(assets::CheckIcuBodyRefsAgainstContext({ref(0x11)}, true, designated, false, why));
    BOOST_CHECK(assets::CheckIcuBodyRefsAgainstContext({ref(0x11), ref(0x22)}, true, designated, false, why));
    // A ref NOT in the designated set is rejected (the bug being fixed).
    BOOST_CHECK(!assets::CheckIcuBodyRefsAgainstContext({ref(0x33)}, true, designated, false, why));
    BOOST_CHECK(!assets::CheckIcuBodyRefsAgainstContext({ref(0x11), ref(0x33)}, true, designated, false, why));

    // Required context: ALL designated must be affirmed; subset/incomplete/bogus all rejected.
    BOOST_CHECK(!assets::CheckIcuBodyRefsAgainstContext({ref(0x11)}, true, designated, /*required=*/true, why));
    BOOST_CHECK(assets::CheckIcuBodyRefsAgainstContext({ref(0x11), ref(0x22)}, true, designated, true, why));
    BOOST_CHECK(!assets::CheckIcuBodyRefsAgainstContext({ref(0x11), ref(0x33)}, true, designated, true, why));
}

BOOST_AUTO_TEST_SUITE_END()
