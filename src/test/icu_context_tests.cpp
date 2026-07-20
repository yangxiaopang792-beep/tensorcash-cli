// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/icu_payload.h>
#include <assets/icu_acceptance.h>

#include <hash.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

using assets::ValidateIcuContext;

namespace {

uint256 H(char c) { return uint256::FromHex(std::string(64, c)).value(); }

std::string Sha256Hex(const std::string& s) {
    unsigned char d[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(s.data()), s.size()).Finalize(d);
    return HexStr(std::vector<unsigned char>(d, d + CSHA256::OUTPUT_SIZE));
}

UniValue Bodies(const std::vector<std::string>& blobs) {
    UniValue b(UniValue::VOBJ);
    for (const std::string& blob : blobs) b.pushKV(Sha256Hex(blob), blob);
    return b;
}

UniValue Ctx(const std::string& acceptance, const UniValue& bodies,
             const char* spec = "TSC-ICU-CONTEXT-1", int parse_version = 1) {
    UniValue m(UniValue::VOBJ);
    m.pushKV("spec", spec);
    m.pushKV("parse_version", parse_version);
    m.pushKV("acceptance", acceptance);
    m.pushKV("bodies", bodies);
    return m;
}

// A canonical text carrying two unique clause substrings (CRLF-normalized, as the
// validator compares against NormalizeCanonicalText output).
const std::string kDoc =
    "PREAMBLE.\r\nCLAUSE SEVEN: power of attorney.\r\nMIDDLE.\r\n"
    "CLAUSE ELEVEN: sanctioned burn.\r\nEND.\r\n";

const std::string kClause7 = "CLAUSE SEVEN: power of attorney.";
const std::string kClause11 = "CLAUSE ELEVEN: sanctioned burn.";

} // namespace

BOOST_AUTO_TEST_SUITE(icu_context_tests)

BOOST_AUTO_TEST_CASE(valid_required_map_passes) {
    std::string err;
    BOOST_CHECK_MESSAGE(ValidateIcuContext(Ctx("required", Bodies({kClause7, kClause11})), kDoc, err), err);
}

BOOST_AUTO_TEST_CASE(whole_document_body_passes) {
    std::string err;
    // Single body == full text: key is raw_sha256_hex(canonical_text) -- the same digest as
    // icu_plain_commit/canonical_hash but raw-digest hex, NOT uint256 display order; the
    // is_whole_document branch bypasses the uniqueness check.
    BOOST_CHECK_MESSAGE(ValidateIcuContext(Ctx("optional", Bodies({kDoc})), kDoc, err), err);
}

BOOST_AUTO_TEST_CASE(wrong_key_rejected) {
    std::string err;
    UniValue bodies(UniValue::VOBJ);
    bodies.pushKV(std::string(64, '0'), kClause7); // key != SHA256(value)
    BOOST_CHECK(!ValidateIcuContext(Ctx("required", bodies), kDoc, err));
}

BOOST_AUTO_TEST_CASE(non_substring_rejected) {
    std::string err;
    BOOST_CHECK(!ValidateIcuContext(Ctx("required", Bodies({"NOT IN THE DOCUMENT"})), kDoc, err));
}

BOOST_AUTO_TEST_CASE(non_unique_body_rejected) {
    std::string err;
    const std::string dup = "ALPHA BETA ALPHA"; // "ALPHA" appears twice
    BOOST_CHECK(!ValidateIcuContext(Ctx("required", Bodies({"ALPHA"})), dup, err));
}

BOOST_AUTO_TEST_CASE(bad_spec_rejected) {
    std::string err;
    BOOST_CHECK(!ValidateIcuContext(Ctx("required", Bodies({kClause7}), "ATAI-ICU-CONTEXT-1"), kDoc, err));
}

BOOST_AUTO_TEST_CASE(unknown_parse_version_rejected) {
    std::string err;
    BOOST_CHECK(!ValidateIcuContext(Ctx("required", Bodies({kClause7}), "TSC-ICU-CONTEXT-1", 2), kDoc, err));
}

BOOST_AUTO_TEST_CASE(bad_acceptance_rejected) {
    std::string err;
    BOOST_CHECK(!ValidateIcuContext(Ctx("maybe", Bodies({kClause7})), kDoc, err));
}

BOOST_AUTO_TEST_CASE(empty_bodies_rejected) {
    std::string err;
    BOOST_CHECK(!ValidateIcuContext(Ctx("optional", UniValue(UniValue::VOBJ)), kDoc, err));
}

// --- Adversarial parsing (must be built from raw JSON: programmatic pushKV de-dups) ------

BOOST_AUTO_TEST_CASE(duplicate_top_level_key_rejected) {
    std::string err;
    const std::string h = Sha256Hex(kClause7);
    const std::string json =
        "{\"spec\":\"TSC-ICU-CONTEXT-1\",\"parse_version\":1,\"acceptance\":\"optional\","
        "\"bodies\":{\"" + h + "\":\"" + kClause7 + "\"},\"acceptance\":\"required\"}";
    UniValue m;
    BOOST_REQUIRE(m.read(json));   // UniValue::read preserves the duplicate "acceptance"
    BOOST_CHECK(!ValidateIcuContext(m, kDoc, err));
}

BOOST_AUTO_TEST_CASE(duplicate_body_key_rejected) {
    std::string err;
    const std::string h = Sha256Hex(kClause7);
    const std::string json =
        "{\"spec\":\"TSC-ICU-CONTEXT-1\",\"parse_version\":1,\"acceptance\":\"optional\","
        "\"bodies\":{\"" + h + "\":\"" + kClause7 + "\",\"" + h + "\":\"" + kClause7 + "\"}}";
    UniValue m;
    BOOST_REQUIRE(m.read(json));
    BOOST_CHECK(!ValidateIcuContext(m, kDoc, err));
}

BOOST_AUTO_TEST_CASE(unknown_top_level_field_rejected) {
    std::string err;
    const std::string h = Sha256Hex(kClause7);
    const std::string json =
        "{\"spec\":\"TSC-ICU-CONTEXT-1\",\"parse_version\":1,\"acceptance\":\"optional\","
        "\"bodies\":{\"" + h + "\":\"" + kClause7 + "\"},\"labels\":{\"x\":\"y\"}}";
    UniValue m;
    BOOST_REQUIRE(m.read(json));
    BOOST_CHECK(!ValidateIcuContext(m, kDoc, err));
}

BOOST_AUTO_TEST_CASE(non_integer_parse_version_rejected) {
    std::string err;
    const std::string h = Sha256Hex(kClause7);
    const std::string json =
        "{\"spec\":\"TSC-ICU-CONTEXT-1\",\"parse_version\":1.5,\"acceptance\":\"optional\","
        "\"bodies\":{\"" + h + "\":\"" + kClause7 + "\"}}";
    UniValue m;
    BOOST_REQUIRE(m.read(json));   // 1.5 is a valid JSON number; getInt<int>() must not throw out
    BOOST_CHECK(!ValidateIcuContext(m, kDoc, err));
}

BOOST_AUTO_TEST_SUITE_END()

// --- TSC-ICU-DOC-ACCEPT-2 message shape -------------------------------------------------

BOOST_AUTO_TEST_SUITE(icu_acceptance_v2_tests)

BOOST_AUTO_TEST_CASE(v2_message_deterministic_and_order_independent) {
    const uint256 a = H('1'), c = H('2'), x = H('3');
    const std::string m1 = assets::BuildAcceptanceMessageV2(a, c, x, "holderA", {"aa", "bb", "cc"});
    const std::string m2 = assets::BuildAcceptanceMessageV2(a, c, x, "holderA", {"cc", "aa", "bb"});
    BOOST_CHECK_EQUAL(m1, m2);  // body_hashes are sorted internally
    BOOST_CHECK(m1.rfind("TSC-ICU-DOC-ACCEPT-2|", 0) == 0);
}

BOOST_AUTO_TEST_CASE(v2_message_field_sensitivity) {
    const uint256 a = H('1'), c = H('2'), x = H('3');
    const std::string base = assets::BuildAcceptanceMessageV2(a, c, x, "holderA", {"aa", "bb"});
    BOOST_CHECK_NE(base, assets::BuildAcceptanceMessageV2(H('9'), c, x, "holderA", {"aa", "bb"}));
    BOOST_CHECK_NE(base, assets::BuildAcceptanceMessageV2(a, H('9'), x, "holderA", {"aa", "bb"}));
    BOOST_CHECK_NE(base, assets::BuildAcceptanceMessageV2(a, c, H('9'), "holderA", {"aa", "bb"}));  // context_hash is bound
    BOOST_CHECK_NE(base, assets::BuildAcceptanceMessageV2(a, c, x, "holderB", {"aa", "bb"}));
    BOOST_CHECK_NE(base, assets::BuildAcceptanceMessageV2(a, c, x, "holderA", {"aa", "cc"}));        // body set matters
    BOOST_CHECK_NE(base, assets::BuildAcceptanceMessageV2(a, c, x, "holderA", {"aa"}));              // subset differs
}

BOOST_AUTO_TEST_CASE(v2_distinct_from_v1) {
    const uint256 a = H('1'), c = H('2'), x = H('3');
    const std::string v2 = assets::BuildAcceptanceMessageV2(a, c, x, "holderA", {"aa"});
    const std::string v1 = assets::BuildAcceptanceMessage(assets::IcuAcceptanceMode::ACKNOWLEDGE, a, c, "holderA");
    BOOST_CHECK_NE(v1, v2);
    BOOST_CHECK(v2.find("TSC-ICU-DOC-ACCEPT-2") == 0);
    BOOST_CHECK(v1.find("TSC-ICU-DOC-ACCEPT-1") == 0);
}

BOOST_AUTO_TEST_SUITE_END()

// --- Option A inline-context helpers ----------------------------------------------------
// ComposeCanonicalTextWithInlineContext / SerializeCanonicalIcuContext / ExtractInlineIcuContext /
// HasInlineIcuContextMarker / VerifyIcuPlainCommit, plus BuildAcceptanceMessageV3 (icu_acceptance.h).

namespace {

using assets::ComposeCanonicalTextWithInlineContext;
using assets::ExtractInlineIcuContext;
using assets::HasInlineIcuContextMarker;
using assets::SerializeCanonicalIcuContext;
using assets::VerifyIcuPlainCommit;
using assets::IcuContextBinding;

// SHA256(text) as a uint256 (raw digest order, matching CanonicalIcuPayload::GetCanonicalHash()).
uint256 Sha256U256(const std::string& s) {
    CSHA256 hasher;
    uint256 out;
    hasher.Write(reinterpret_cast<const unsigned char*>(s.data()), s.size()).Finalize(out.begin());
    return out;
}

// Wrap a normalized canonical text in a CanonicalIcuPayload (plaintext, public).
assets::CanonicalIcuPayload PayloadFromText(const std::string& text) {
    assets::CanonicalIcuPayload p;
    p.canonical_text.assign(text.begin(), text.end());
    return p;
}

// A couple of distinct, non-empty clause bodies that contain no delimiters.
const std::string kBody = "These are the human-readable terms of the instrument.";
const std::string kClauseA = "Clause A: the holder grants a limited power of attorney.";
const std::string kClauseB = "Clause B: assets may be burned under sanction.";
const std::string kClauseC = "Clause C: governing law is the courts of Tortola.";

} // namespace

BOOST_AUTO_TEST_SUITE(icu_inline_context_tests)

// (1) Compose happy path.
BOOST_AUTO_TEST_CASE(compose_happy_path) {
    UniValue ctx;
    std::vector<std::string> keys;
    std::string err;
    auto text = ComposeCanonicalTextWithInlineContext(
        kBody, {kClauseA, kClauseB, kClauseC}, "required", ctx, keys, err);
    BOOST_REQUIRE_MESSAGE(text, err);

    BOOST_CHECK_NE(text->find(assets::ICU_CONTEXT_BLOCK_BEGIN), std::string::npos);
    BOOST_CHECK_NE(text->find(assets::ICU_CONTEXT_BLOCK_END), std::string::npos);
    BOOST_CHECK_NE(text->find(kBody), std::string::npos);

    // out_context has the four required fields with the right shape.
    BOOST_CHECK(ctx.isObject());
    BOOST_CHECK_EQUAL(ctx["spec"].get_str(), std::string(assets::ICU_CONTEXT_SPEC_V1));
    BOOST_CHECK_EQUAL(ctx["parse_version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(ctx["acceptance"].get_str(), "required");
    BOOST_REQUIRE(ctx["bodies"].isObject());

    // out_body_keys: right count, in clause order, each == lowercase-hex SHA256(normalized clause).
    BOOST_REQUIRE_EQUAL(keys.size(), 3u);
    BOOST_CHECK_EQUAL(keys[0], Sha256Hex(kClauseA));
    BOOST_CHECK_EQUAL(keys[1], Sha256Hex(kClauseB));
    BOOST_CHECK_EQUAL(keys[2], Sha256Hex(kClauseC));
    BOOST_CHECK_EQUAL(ctx["bodies"].size(), 3);
    for (const std::string& k : keys) {
        BOOST_CHECK(ctx["bodies"].exists(k));
        BOOST_CHECK_EQUAL(Sha256Hex(ctx["bodies"][k].get_str()), k);  // key == SHA256(value)
    }
}

// (2) Compose rejects.
BOOST_AUTO_TEST_CASE(compose_rejects_empty_clause_list) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    BOOST_CHECK(!ComposeCanonicalTextWithInlineContext(kBody, {}, "required", ctx, keys, err));
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(compose_rejects_clause_empty_after_normalization) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    // Trailing whitespace-only clause normalizes to empty (trim of trailing space/tab).
    BOOST_CHECK(!ComposeCanonicalTextWithInlineContext(kBody, {"   \t  "}, "required", ctx, keys, err));
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(compose_rejects_duplicate_clauses) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    BOOST_CHECK(!ComposeCanonicalTextWithInlineContext(kBody, {kClauseA, kClauseA}, "required", ctx, keys, err));
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(compose_rejects_body_with_delimiter) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    const std::string poisoned = std::string("intro ") + assets::ICU_CONTEXT_BLOCK_BEGIN + " tail";
    BOOST_CHECK(!ComposeCanonicalTextWithInlineContext(poisoned, {kClauseA}, "required", ctx, keys, err));
}

BOOST_AUTO_TEST_CASE(compose_rejects_clause_with_delimiter) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    const std::string poisoned = std::string("Clause: ") + assets::ICU_CONTEXT_BLOCK_END;
    BOOST_CHECK(!ComposeCanonicalTextWithInlineContext(kBody, {poisoned}, "required", ctx, keys, err));
}

BOOST_AUTO_TEST_CASE(compose_rejects_invalid_acceptance) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    BOOST_CHECK(!ComposeCanonicalTextWithInlineContext(kBody, {kClauseA}, "maybe", ctx, keys, err));
    BOOST_CHECK(!err.empty());
}

// (3) Serialize determinism + sorted keys + top-level key order.
BOOST_AUTO_TEST_CASE(serialize_is_deterministic_and_sorted) {
    // Build a context with body keys inserted in NON-sorted order on purpose.
    const std::string vA = kClauseA, vB = kClauseB, vC = kClauseC;
    std::vector<std::string> kv = {Sha256Hex(vA), Sha256Hex(vB), Sha256Hex(vC)};
    std::vector<std::string> sorted_keys = kv;
    std::sort(sorted_keys.begin(), sorted_keys.end());

    UniValue bodies(UniValue::VOBJ);
    // Insert in reverse-sorted order so getKeys() insertion order != sorted order.
    for (auto it = kv.rbegin(); it != kv.rend(); ++it) {
        const std::string& k = *it;
        const std::string& v = (k == Sha256Hex(vA)) ? vA : (k == Sha256Hex(vB)) ? vB : vC;
        bodies.pushKV(k, v);
    }
    UniValue ctx = Ctx("required", bodies);

    std::string err;
    auto s1 = SerializeCanonicalIcuContext(ctx, err);
    BOOST_REQUIRE_MESSAGE(s1, err);
    auto s2 = SerializeCanonicalIcuContext(ctx, err);
    BOOST_REQUIRE(s2);
    BOOST_CHECK_EQUAL(*s1, *s2);  // byte-identical across calls

    // Top-level key order: acceptance, bodies, parse_version, spec.
    const size_t pAcc = s1->find("\"acceptance\":");
    const size_t pBod = s1->find("\"bodies\":");
    const size_t pPv  = s1->find("\"parse_version\":");
    const size_t pSpec = s1->find("\"spec\":");
    BOOST_REQUIRE(pAcc != std::string::npos && pBod != std::string::npos &&
                  pPv != std::string::npos && pSpec != std::string::npos);
    BOOST_CHECK(pAcc < pBod);
    BOOST_CHECK(pBod < pPv);
    BOOST_CHECK(pPv < pSpec);

    // Body keys appear in sorted order within the serialized output.
    size_t prev = 0;
    for (const std::string& k : sorted_keys) {
        const size_t at = s1->find("\"" + k + "\"");
        BOOST_REQUIRE(at != std::string::npos);
        BOOST_CHECK(at >= prev);
        prev = at;
    }
}

// (4) Round-trip: Compose -> Normalize -> Extract; and SHA256(normalized) == GetCanonicalHash().
BOOST_AUTO_TEST_CASE(roundtrip_compose_normalize_extract) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    auto text = ComposeCanonicalTextWithInlineContext(
        kBody, {kClauseA, kClauseB}, "required", ctx, keys, err);
    BOOST_REQUIRE_MESSAGE(text, err);

    auto norm = assets::NormalizeCanonicalText(*text);
    BOOST_REQUIRE(norm);

    bool present = false;
    std::string xerr;
    auto extracted = ExtractInlineIcuContext(*norm, present, xerr);
    BOOST_CHECK(present);
    BOOST_REQUIRE_MESSAGE(extracted, xerr);
    BOOST_CHECK(xerr.empty());

    // Extracted bodies match out_context's bodies (key set + values).
    const UniValue& want = ctx["bodies"];
    const UniValue& got = (*extracted)["bodies"];
    BOOST_REQUIRE(got.isObject());
    BOOST_CHECK_EQUAL(got.size(), want.size());
    for (const std::string& k : want.getKeys()) {
        BOOST_REQUIRE(got.exists(k));
        BOOST_CHECK_EQUAL(got[k].get_str(), want[k].get_str());
    }

    // SHA256(normalized text) == GetCanonicalHash() of a payload whose canonical_text = norm bytes.
    assets::CanonicalIcuPayload p = PayloadFromText(*norm);
    BOOST_CHECK(p.GetCanonicalHash() == Sha256U256(*norm));
}

// (5) Mutability: icu_plain_commit moves with any clause OR body change; identical inputs match.
BOOST_AUTO_TEST_CASE(mutability_hash_moves_with_content) {
    auto compose_norm = [](const std::string& body, const std::vector<std::string>& clauses) {
        UniValue ctx; std::vector<std::string> keys; std::string err;
        auto t = ComposeCanonicalTextWithInlineContext(body, clauses, "required", ctx, keys, err);
        BOOST_REQUIRE_MESSAGE(t, err);
        auto n = assets::NormalizeCanonicalText(*t);
        BOOST_REQUIRE(n);
        return Sha256U256(*n);
    };

    const uint256 baseline = compose_norm(kBody, {kClauseA, kClauseB});

    // Change ONE clause -> different hash.
    const uint256 changed_clause = compose_norm(kBody, {kClauseA, kClauseC});
    BOOST_CHECK(baseline != changed_clause);

    // Change only the human body (same clauses) -> different hash.
    const uint256 changed_body = compose_norm(kBody + " EXTRA.", {kClauseA, kClauseB});
    BOOST_CHECK(baseline != changed_body);

    // Identical inputs -> identical hash.
    const uint256 again = compose_norm(kBody, {kClauseA, kClauseB});
    BOOST_CHECK(baseline == again);
}

// (6) Extract edge cases.
BOOST_AUTO_TEST_CASE(extract_no_block) {
    bool present = true;  // ensure it gets reset to false
    std::string err = "stale";
    auto r = ExtractInlineIcuContext("just some prose with no block\r\n", present, err);
    BOOST_CHECK(!present);
    BOOST_CHECK(!r);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(extract_two_begin_delimiters) {
    const std::string B = assets::ICU_CONTEXT_BLOCK_BEGIN;
    const std::string txt = B + "\r\n{}\r\n" + B + "\r\n";
    bool present = false; std::string err;
    auto r = ExtractInlineIcuContext(txt, present, err);
    BOOST_CHECK(present);
    BOOST_CHECK(!r);
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(extract_begin_without_end) {
    const std::string txt = std::string(assets::ICU_CONTEXT_BLOCK_BEGIN) + "\r\n{}\r\n";
    bool present = false; std::string err;
    auto r = ExtractInlineIcuContext(txt, present, err);
    BOOST_CHECK(present);
    BOOST_CHECK(!r);
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(extract_malformed_json) {
    const std::string txt = std::string(assets::ICU_CONTEXT_BLOCK_BEGIN) + "\r\n{not json\r\n" +
                            assets::ICU_CONTEXT_BLOCK_END + "\r\n";
    bool present = false; std::string err;
    auto r = ExtractInlineIcuContext(txt, present, err);
    BOOST_CHECK(present);
    BOOST_CHECK(!r);
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(extract_bad_body_key_invalid_context) {
    // A well-formed JSON object but a body key that does NOT equal SHA256(value).
    const std::string json =
        "{\"acceptance\":\"required\",\"bodies\":{\"" + std::string(64, '0') + "\":\"" + kClauseA +
        "\"},\"parse_version\":1,\"spec\":\"TSC-ICU-CONTEXT-1\"}";
    const std::string txt = std::string(assets::ICU_CONTEXT_BLOCK_BEGIN) + "\r\n" + json + "\r\n" +
                            assets::ICU_CONTEXT_BLOCK_END + "\r\n";
    bool present = false; std::string err;
    auto r = ExtractInlineIcuContext(txt, present, err);
    BOOST_CHECK(present);
    BOOST_CHECK(!r);
    BOOST_CHECK(!err.empty());
}

// (7) ValidateIcuContext InlineV2 vs SubstringV1.
BOOST_AUTO_TEST_CASE(validate_inline_v2_skips_substring_binding) {
    // Body value is NOT a substring of the passed canonical text.
    UniValue ctx = Ctx("required", Bodies({kClauseA}));
    const std::string unrelated = "totally unrelated canonical text\r\n";
    std::string err;

    // SubstringV1 (default) fails: not a substring.
    BOOST_CHECK(!ValidateIcuContext(ctx, unrelated, err, IcuContextBinding::SubstringV1));
    // InlineV2 passes: the substring/uniqueness tie is skipped.
    BOOST_CHECK_MESSAGE(ValidateIcuContext(ctx, unrelated, err, IcuContextBinding::InlineV2), err);

    // key==SHA256(value) is still enforced under InlineV2.
    UniValue bad(UniValue::VOBJ);
    bad.pushKV(std::string(64, '0'), kClauseA);  // wrong key
    UniValue bad_ctx = Ctx("required", bad);
    BOOST_CHECK(!ValidateIcuContext(bad_ctx, unrelated, err, IcuContextBinding::InlineV2));
}

// (8) HasInlineIcuContextMarker.
BOOST_AUTO_TEST_CASE(marker_detection) {
    auto bytes = [](const std::string& s) {
        return std::vector<unsigned char>(s.begin(), s.end());
    };
    BOOST_CHECK(HasInlineIcuContextMarker(bytes(assets::ICU_CONTEXT_INLINE_MARKER_JSON)));
    BOOST_CHECK(!HasInlineIcuContextMarker({}));                                  // empty
    BOOST_CHECK(!HasInlineIcuContextMarker(bytes("{\"other\":\"value\"}")));       // arbitrary JSON
    // A full context object is not the marker.
    std::string err;
    auto full = SerializeCanonicalIcuContext(Ctx("required", Bodies({kClauseA})), err);
    BOOST_REQUIRE(full);
    BOOST_CHECK(!HasInlineIcuContextMarker(bytes(*full)));
}

// (9) VerifyIcuPlainCommit.
BOOST_AUTO_TEST_CASE(verify_icu_plain_commit) {
    UniValue ctx; std::vector<std::string> keys; std::string err;
    auto text = ComposeCanonicalTextWithInlineContext(kBody, {kClauseA}, "required", ctx, keys, err);
    BOOST_REQUIRE_MESSAGE(text, err);
    auto norm = assets::NormalizeCanonicalText(*text);
    BOOST_REQUIRE(norm);

    assets::CanonicalIcuPayload p = PayloadFromText(*norm);
    const uint256 good = Sha256U256(*norm);
    BOOST_CHECK(VerifyIcuPlainCommit(p, good));
    BOOST_CHECK(!VerifyIcuPlainCommit(p, H('f')));  // wrong declared hash
}

BOOST_AUTO_TEST_SUITE_END()

// --- TSC-ICU-DOC-ACCEPT-3 message shape (10) --------------------------------------------

BOOST_AUTO_TEST_SUITE(icu_acceptance_v3_tests)

BOOST_AUTO_TEST_CASE(v3_message_binds_fields_and_prefix) {
    const uint256 asset = H('1'), commit = H('2');
    const std::string msg = assets::BuildAcceptanceMessageV3(
        assets::IcuAcceptanceMode::ACKNOWLEDGE, asset, commit, "holderX", {"bb", "aa"});

    BOOST_CHECK(msg.rfind("TSC-ICU-DOC-ACCEPT-3", 0) == 0);   // begins with the v3 tag
    BOOST_CHECK_NE(msg.find(asset.ToString()), std::string::npos);   // binds asset_id
    BOOST_CHECK_NE(msg.find("acknowledge"), std::string::npos);      // binds mode
    BOOST_CHECK_NE(msg.find(commit.ToString()), std::string::npos);  // binds icu_plain_commit
    BOOST_CHECK_NE(msg.find("holderX"), std::string::npos);          // binds holder
    BOOST_CHECK(msg.find("context_hash") == std::string::npos);      // NO context_hash field
}

BOOST_AUTO_TEST_CASE(v3_body_refs_sorted_order_independent) {
    const uint256 asset = H('1'), commit = H('2');
    const std::string out_of_order = assets::BuildAcceptanceMessageV3(
        assets::IcuAcceptanceMode::ACKNOWLEDGE, asset, commit, "holderX", {"cc", "aa", "bb"});
    const std::string sorted = assets::BuildAcceptanceMessageV3(
        assets::IcuAcceptanceMode::ACKNOWLEDGE, asset, commit, "holderX", {"aa", "bb", "cc"});
    BOOST_CHECK_EQUAL(out_of_order, sorted);
}

BOOST_AUTO_TEST_CASE(v3_empty_body_refs_is_whole_document) {
    const uint256 asset = H('1'), commit = H('2');
    const std::string whole = assets::BuildAcceptanceMessageV3(
        assets::IcuAcceptanceMode::ACKNOWLEDGE, asset, commit, "holderX", {});
    // Whole-document message: ends at the holder, with no trailing "|<ref>" segments.
    BOOST_CHECK(whole.rfind("holderX") == whole.size() - std::string("holderX").size());

    // Adding a body ref must extend the message (a ref is appended after the holder).
    const std::string with_ref = assets::BuildAcceptanceMessageV3(
        assets::IcuAcceptanceMode::ACKNOWLEDGE, asset, commit, "holderX", {"aa"});
    BOOST_CHECK_NE(whole, with_ref);
    BOOST_CHECK(with_ref.rfind("holderX|aa") != std::string::npos);
}

// --- CanonicalizeIcuBandJson (general band encoder, OPTION_SERIES_FREEZE.md §6.1) ---------------

static std::string CanonBand(const UniValue& v)
{
    std::string err;
    auto bytes = assets::CanonicalizeIcuBandJson(v, err);
    BOOST_REQUIRE_MESSAGE(bytes.has_value(), "CanonicalizeIcuBandJson failed: " << err);
    return std::string(bytes->begin(), bytes->end());
}

BOOST_AUTO_TEST_CASE(canonical_band_sorts_keys_recursively_compact)
{
    // The TSC-ICU-META-1 shape: keys MUST come out sorted at every level, with no whitespace.
    UniValue opt(UniValue::VOBJ);
    opt.pushKV("spec", "TSC-ICU-OPTSERIES-1");        // inserted out of order on purpose
    opt.pushKV("descriptor", "deadbeef");
    opt.pushKV("parse_version", 1);
    UniValue meta(UniValue::VOBJ);
    meta.pushKV("spec", "TSC-ICU-META-1");
    meta.pushKV("optseries", opt);

    BOOST_CHECK_EQUAL(CanonBand(meta),
        "{\"optseries\":{\"descriptor\":\"deadbeef\",\"parse_version\":1,\"spec\":\"TSC-ICU-OPTSERIES-1\"},"
        "\"spec\":\"TSC-ICU-META-1\"}");
}

BOOST_AUTO_TEST_CASE(canonical_band_arrays_keep_source_order_and_escape_strings)
{
    UniValue arr(UniValue::VARR);
    arr.push_back(3); arr.push_back(1); arr.push_back(2);
    UniValue o(UniValue::VOBJ);
    o.pushKV("arr", arr);
    o.pushKV("s", "a\"b\\c\n");      // quote, backslash, newline must escape
    o.pushKV("b", true);
    o.pushKV("z", UniValue(UniValue::VNULL));
    BOOST_CHECK_EQUAL(CanonBand(o),
        "{\"arr\":[3,1,2],\"b\":true,\"s\":\"a\\\"b\\\\c\\n\",\"z\":null}");
}

BOOST_AUTO_TEST_CASE(canonical_band_number_grammar)
{
    auto num_ok = [](const std::string& lex) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("n", UniValue(UniValue::VNUM, lex));
        std::string err;
        return assets::CanonicalizeIcuBandJson(o, err).has_value();
    };
    // Canonical integers (incl. values > int32 / large u64) accepted.
    for (const char* ok : {"0", "5", "-5", "3000000000", "2099999997690000"}) {
        BOOST_CHECK_MESSAGE(num_ok(ok), std::string("should accept ") + ok);
    }
    // Floats, exponents, signed zero, leading zeros, junk rejected (fail-closed).
    for (const char* bad : {"1.5", "1e3", "-0", "01", "00", "+5", "", "NaN", "0x10"}) {
        BOOST_CHECK_MESSAGE(!num_ok(bad), std::string("should reject ") + bad);
    }
    // A large u64 emits its exact lexeme (no int truncation).
    UniValue o(UniValue::VOBJ); o.pushKV("im", UniValue(UniValue::VNUM, "3000000000"));
    BOOST_CHECK_EQUAL(CanonBand(o), "{\"im\":3000000000}");
}

BOOST_AUTO_TEST_CASE(canonical_band_rejects_duplicate_keys)
{
    // A genuine duplicate-key object. pushKV() de-duplicates (replaces the
    // existing value), so it can NOT build one — but untrusted JSON reaches the
    // canonicalizer via UniValue::read(), whose parser appends keys verbatim,
    // so duplicates are real on that path and the encoder MUST refuse them.
    UniValue o;
    BOOST_REQUIRE(o.read("{\"a\":1,\"a\":2}"));
    BOOST_REQUIRE(o.isObject());
    BOOST_REQUIRE_EQUAL(o.getKeys().size(), 2U);   // read() kept both "a" keys
    std::string err;
    BOOST_CHECK(!assets::CanonicalizeIcuBandJson(o, err).has_value());
    BOOST_CHECK(err.find("duplicate object key") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
