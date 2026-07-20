// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/icu_payload.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(icu_payload_tests)

BOOST_AUTO_TEST_CASE(normalize_ascii_crlf)
{
    const std::string input = "Hello\nWorld\rGoodbye";
    std::optional<std::string> result = assets::NormalizeCanonicalText(input);
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(*result, "Hello\r\nWorld\r\nGoodbye");
}

BOOST_AUTO_TEST_CASE(normalize_trim_trailing_whitespace)
{
    const std::string input = "Line with space \r\nTrailing tab\t";
    std::optional<std::string> result = assets::NormalizeCanonicalText(input);
    BOOST_REQUIRE(result);
    BOOST_CHECK_NE(result->find("\r\nTrailing tab"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(normalize_accept_unicode)
{
    const std::string accented = "caf\xc3\xa9"; // café
    std::optional<std::string> result = assets::NormalizeCanonicalText(accented);
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(*result, accented);

    const std::string kanji = "契約文書"; // Japanese for "contract document"
    result = assets::NormalizeCanonicalText(kanji);
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(*result, kanji);
}

BOOST_AUTO_TEST_CASE(normalize_combining_sequence_canonicalizes)
{
    // e + COMBINING ACUTE ACCENT should normalize to precomposed "é"
    const std::string combining = "e\xCC\x81";
    std::optional<std::string> result = assets::NormalizeCanonicalText(combining);
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(*result, std::string("\xc3\xa9"));
}

BOOST_AUTO_TEST_CASE(normalize_reject_control_chars)
{
    const std::string control = std::string("Valid") + '\x01';
    std::optional<std::string> result = assets::NormalizeCanonicalText(control);
    BOOST_CHECK(!result);
}

BOOST_AUTO_TEST_SUITE_END()
