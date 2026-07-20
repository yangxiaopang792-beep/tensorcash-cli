// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/icu_payload.h>
#include <assets/asset.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/hmac_sha256.h>
#include <hash.h>
#include <random.h>
#include <util/strencodings.h>
#include <univalue.h>
#include <wallet/crypter.h>

#include <boost/locale.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iterator>
#include <locale>
#include <set>
#include <sstream>

#include <zstd.h>

namespace assets {

namespace {

constexpr size_t ICU_CHUNK_TRAILER_SIZE = 4 /* magic */ + 1 /* version */ + 1 /* compression */ +
                                          1 /* encryption_mode */ + 1 /* flags */ + 32 /* witness_hash */;
constexpr unsigned char ICU_CHUNK_TRAILER_MAGIC[4] = {'I', 'C', 'U', 'M'};

bool DecodeUtf8(const char*& it, const char* end, uint32_t& cp)
{
    const unsigned char lead = static_cast<unsigned char>(*it);
    if (lead < 0x80) {
        cp = lead;
        ++it;
        return true;
    }
    if ((lead >> 5) == 0x6) {
        if (end - it < 2) return false;
        unsigned char ch1 = static_cast<unsigned char>(it[1]);
        if ((ch1 & 0xC0) != 0x80) return false;
        cp = ((lead & 0x1F) << 6) | (ch1 & 0x3F);
        if (cp < 0x80) return false;
        it += 2;
        return true;
    }
    if ((lead >> 4) == 0xE) {
        if (end - it < 3) return false;
        unsigned char ch1 = static_cast<unsigned char>(it[1]);
        unsigned char ch2 = static_cast<unsigned char>(it[2]);
        if ((ch1 & 0xC0) != 0x80 || (ch2 & 0xC0) != 0x80) return false;
        cp = ((lead & 0x0F) << 12) | ((ch1 & 0x3F) << 6) | (ch2 & 0x3F);
        if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        it += 3;
        return true;
    }
    if ((lead >> 3) == 0x1E) {
        if (end - it < 4) return false;
        unsigned char ch1 = static_cast<unsigned char>(it[1]);
        unsigned char ch2 = static_cast<unsigned char>(it[2]);
        unsigned char ch3 = static_cast<unsigned char>(it[3]);
        if ((ch1 & 0xC0) != 0x80 || (ch2 & 0xC0) != 0x80 || (ch3 & 0xC0) != 0x80) return false;
        cp = ((lead & 0x07) << 18) | ((ch1 & 0x3F) << 12) | ((ch2 & 0x3F) << 6) | (ch3 & 0x3F);
        if (cp < 0x10000 || cp > 0x10FFFF) return false;
        it += 4;
        return true;
    }
    return false;
}

void EncodeUtf8(uint32_t cp, std::string& out)
{
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool IsAllowedCodePoint(uint32_t cp)
{
    if (cp <= 0x1F) {
        return cp == 0x09 || cp == 0x0A || cp == 0x0D;
    }
    if (cp == 0x7F) return false;                    // DEL
    if (cp >= 0x80 && cp <= 0x9F) return false;      // C1 controls
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // surrogates
    if (cp > 0x10FFFF) return false;                 // out of range

    // Unicode non-characters: U+FDD0..U+FDEF and the last two code points of EVERY plane
    // (xFFFE / xFFFF). Each clause body is bound by SHA256 over a normalized excerpt, so these
    // must be rejected or the displayed-vs-committed bytes can diverge.
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return false;
    if ((cp & 0xFFFE) == 0xFFFE) return false;

    // Zero-width / invisible characters that can hide a displayed-vs-committed difference.
    if (cp == 0x200B || cp == 0x200C || cp == 0x200D) return false;  // ZWSP, ZWNJ, ZWJ
    if (cp == 0x2060) return false;                  // word joiner
    if (cp == 0xFEFF) return false;                  // ZWNBSP / BOM

    // Bidirectional embedding / override / isolate controls that can reorder displayed text.
    if (cp >= 0x202A && cp <= 0x202E) return false;  // LRE RLE PDF LRO RLO
    if (cp >= 0x2066 && cp <= 0x2069) return false;  // LRI RLI FSI PDI

    return true;
}

bool IsAsciiTrailingWhitespace(uint32_t cp)
{
    return cp == 0x20 || cp == 0x09;
}

} // namespace

const std::locale& CanonicalLocale()
{
    static const std::locale kLocale = []() {
        boost::locale::generator gen;
        try {
            return gen("en_US.UTF-8");
        } catch (const std::exception&) {
            return gen("");
        }
    }();
    return kLocale;
}

std::optional<std::string> NormalizeCanonicalText(const std::string& input) {
    std::string normalized;
    try {
        normalized = boost::locale::normalize(input, boost::locale::norm_nfc, CanonicalLocale());
    } catch (const std::exception&) {
        return std::nullopt;
    }

    std::string result;
    result.reserve(normalized.size());

    bool prev_was_cr = false;
    size_t last_non_ws_len = 0;

    const char* it = normalized.data();
    const char* end = it + normalized.size();
    while (it != end) {
        uint32_t cp{0};
        if (!DecodeUtf8(it, end, cp)) {
            return std::nullopt;
        }

        if (cp == 0x0D) {
            result.push_back('\r');
            result.push_back('\n');
            last_non_ws_len = result.size();
            prev_was_cr = true;
            continue;
        }
        if (cp == 0x0A) {
            if (prev_was_cr) {
                prev_was_cr = false;
                continue;
            }
            result.push_back('\r');
            result.push_back('\n');
            last_non_ws_len = result.size();
            prev_was_cr = false;
            continue;
        }

        prev_was_cr = false;

        if (!IsAllowedCodePoint(cp)) {
            return std::nullopt;
        }

        EncodeUtf8(cp, result);
        if (!IsAsciiTrailingWhitespace(cp)) {
            last_non_ws_len = result.size();
        }
    }

    if (last_non_ws_len < result.size()) {
        result.resize(last_non_ws_len);
    }

    if (!result.empty() && result.back() == '\r') {
        result.push_back('\n');
    }

    return result;
}

bool VerifyWitnessLinkage(const std::vector<unsigned char>& witness_bundle, const uint256& expected_hash) {
    // Try to parse witness_bundle as JSON
    try {
        std::string witness_str(witness_bundle.begin(), witness_bundle.end());
        UniValue witness_json;
        if (!witness_json.read(witness_str)) {
            // Not valid JSON, try searching for hex string directly
            std::string expected_hex = expected_hash.ToString();
            return witness_str.find(expected_hex) != std::string::npos;
        }

        // Check if "canonical_hash" field exists
        if (witness_json.isObject() && witness_json.exists("canonical_hash")) {
            std::string hash_str = witness_json["canonical_hash"].get_str();
            auto parsed_hash = uint256::FromHex(hash_str);
            if (parsed_hash && *parsed_hash == expected_hash) {
                return true;
            }
        }

        // Fallback: search for hash string anywhere in JSON
        return witness_str.find(expected_hash.ToString()) != std::string::npos;
    } catch (const std::exception&) {
        return false;
    }
}

static std::string Sha256HexLower(const std::string& s) {
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(s.data()), s.size()).Finalize(digest);
    return HexStr(std::vector<unsigned char>(digest, digest + CSHA256::OUTPUT_SIZE));
}

// UniValue::read preserves duplicate keys (operator[] returns the first match), so a
// duplicate is a parser-bifurcation surface for committed protocol JSON: reject it.
static bool HasDuplicateKeys(const UniValue& obj) {
    std::vector<std::string> keys = obj.getKeys();
    std::sort(keys.begin(), keys.end());
    return std::adjacent_find(keys.begin(), keys.end()) != keys.end();
}

bool ValidateIcuContext(const UniValue& meta, const std::string& normalized_canonical, std::string& error,
                        IcuContextBinding binding) {
    if (!meta.isObject()) { error = "context metadata is not a JSON object"; return false; }

    if (HasDuplicateKeys(meta)) { error = "context has duplicate top-level keys"; return false; }

    // Strict allow-list: exactly these four keys and nothing else (fail-closed against any
    // future/unknown field, which an old validator would otherwise ignore and still accept).
    for (const std::string& k : meta.getKeys()) {
        if (k != "spec" && k != "parse_version" && k != "acceptance" && k != "bodies") {
            error = "unknown top-level field in context: " + k;
            return false;
        }
    }

    const UniValue& spec = meta["spec"];
    if (!spec.isStr() || spec.get_str() != ICU_CONTEXT_SPEC_V1) {
        error = std::string("context spec missing or not ") + ICU_CONTEXT_SPEC_V1;
        return false;
    }

    const UniValue& pv = meta["parse_version"];
    if (!pv.isNum()) { error = "context parse_version missing or not a number"; return false; }
    int parse_version = 0;
    try {
        parse_version = pv.getInt<int>();  // throws on non-integer / out-of-range
    } catch (const std::exception&) {
        error = "context parse_version is not a valid integer";
        return false;
    }
    if (parse_version < 1 || parse_version > ICU_CONTEXT_PARSE_VERSION_MAX) {
        error = "context parse_version unsupported";
        return false;
    }

    const UniValue& acc = meta["acceptance"];
    if (!acc.isStr() || (acc.get_str() != "required" && acc.get_str() != "optional")) {
        error = "context acceptance must be \"required\" or \"optional\"";
        return false;
    }

    const UniValue& bodies = meta["bodies"];
    if (!bodies.isObject() || bodies.size() == 0) {
        error = "context bodies missing or empty";
        return false;
    }
    if (HasDuplicateKeys(bodies)) { error = "context bodies has duplicate keys"; return false; }

    for (const std::string& key : bodies.getKeys()) {
        const UniValue& v = bodies[key];
        if (!v.isStr()) { error = "context body is not a string for key " + key; return false; }
        const std::string& blob = v.get_str();
        if (blob.empty()) { error = "context body is empty for key " + key; return false; }

        if (Sha256HexLower(blob) != key) {
            error = "context body key does not equal SHA256(value) for key " + key;
            return false;
        }

        // InlineV2 (Option A): the body lives inside canonical_text already (it IS the embedded
        // block), so it is covered by icu_plain_commit directly -- the substring/uniqueness tie to
        // the prose is skipped (and would always fail, since the value also appears in the block).
        if (binding == IcuContextBinding::SubstringV1) {
            const size_t first = normalized_canonical.find(blob);
            if (first == std::string::npos) {
                error = "context body is not a substring of canonical text for key " + key;
                return false;
            }
            const bool is_whole_document = (blob.size() == normalized_canonical.size());
            if (!is_whole_document &&
                normalized_canonical.find(blob, first + 1) != std::string::npos) {
                error = "context body is not unique in canonical text for key " + key;
                return false;
            }
        } else {
            // InlineV2: the substring tie is gone, so the clause text is no longer forced through
            // the ICU text codepoint/normalization rules by virtue of appearing in the prose. A
            // hand-built block could otherwise smuggle escaped controls / non-canonical text that
            // the normal ICU text path rejects. Require the value to be exactly its own
            // NormalizeCanonicalText output, and reject the delimiter strings inside a value.
            auto nblob = NormalizeCanonicalText(blob);
            if (!nblob || *nblob != blob) {
                error = "context body is not canonical (fails ICU text normalization) for key " + key;
                return false;
            }
            if (blob.find(ICU_CONTEXT_BLOCK_BEGIN) != std::string::npos ||
                blob.find(ICU_CONTEXT_BLOCK_END) != std::string::npos) {
                error = "context body contains an ICU context delimiter for key " + key;
                return false;
            }
        }
    }
    return true;
}

// --- Inline TSC-ICU-CONTEXT-1 (Option A: context committed inside canonical_text) --------------

// RFC 8785 (JCS) style JSON string escaping: short escapes for the standard set, \u00xx for other
// C0 controls, raw bytes (incl. multi-byte UTF-8) otherwise. Deterministic, so the embedded bytes
// are reproducible.
static void AppendCanonicalJsonString(const std::string& s, std::string& out) {
    static const char* kHex = "0123456789abcdef";
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\t': out += "\\t";  break;
            case '\n': out += "\\n";  break;
            case '\f': out += "\\f";  break;
            case '\r': out += "\\r";  break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(kHex[(c >> 4) & 0xF]);
                    out.push_back(kHex[c & 0xF]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

std::optional<std::string> SerializeCanonicalIcuContext(const UniValue& meta, std::string& error) {
    if (!meta.isObject()) { error = "context is not an object"; return std::nullopt; }
    const UniValue& acc = meta["acceptance"];
    const UniValue& bodies = meta["bodies"];
    const UniValue& pv = meta["parse_version"];
    const UniValue& spec = meta["spec"];
    if (!acc.isStr() || !bodies.isObject() || !pv.isNum() || !spec.isStr()) {
        error = "context missing required fields"; return std::nullopt;
    }

    // Top-level keys emitted in lexicographic order: acceptance < bodies < parse_version < spec.
    std::string out = "{\"acceptance\":";
    AppendCanonicalJsonString(acc.get_str(), out);
    out += ",\"bodies\":{";
    std::vector<std::string> keys = bodies.getKeys();
    std::sort(keys.begin(), keys.end());
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i) out.push_back(',');
        const UniValue& v = bodies[keys[i]];
        if (!v.isStr()) { error = "context body is not a string for key " + keys[i]; return std::nullopt; }
        AppendCanonicalJsonString(keys[i], out);
        out.push_back(':');
        AppendCanonicalJsonString(v.get_str(), out);
    }
    out += "},\"parse_version\":";
    int pvi = 0;
    try { pvi = pv.getInt<int>(); } catch (const std::exception&) { error = "bad parse_version"; return std::nullopt; }
    out += std::to_string(pvi);
    out += ",\"spec\":";
    AppendCanonicalJsonString(spec.get_str(), out);
    out.push_back('}');
    return out;
}

// --- General canonical-JSON band encoder (TSC-ICU-META-1 and sub-bands) -------------------------

static bool AppendCanonicalJsonValue(const UniValue& v, std::string& out, std::string& error);

// Numbers must be canonical decimal integers: ^-?(0|[1-9][0-9]*)$, excluding "-0". Rejects floats,
// exponents, leading zeros, NaN/Inf (UniValue stores the lexeme, so we validate it byte-for-byte).
static bool AppendCanonicalJsonNumber(const UniValue& v, std::string& out, std::string& error) {
    const std::string s = v.getValStr();
    bool ok = !s.empty();
    size_t i = 0;
    if (ok && s[i] == '-') { i++; ok = (i < s.size()); }
    if (ok) {
        if (s[i] == '0') {
            ok = (i + 1 == s.size()) && (i == 0); // exactly "0" (rejects "-0", "01")
        } else if (s[i] >= '1' && s[i] <= '9') {
            for (size_t j = i + 1; j < s.size() && ok; ++j) ok = (s[j] >= '0' && s[j] <= '9');
        } else {
            ok = false;
        }
    }
    if (!ok) { error = "non-canonical integer JSON number: " + s; return false; }
    out += s;
    return true;
}

static bool AppendCanonicalJsonValue(const UniValue& v, std::string& out, std::string& error) {
    switch (v.getType()) {
        case UniValue::VNULL: out += "null"; return true;
        case UniValue::VBOOL: out += (v.get_bool() ? "true" : "false"); return true;
        case UniValue::VNUM:  return AppendCanonicalJsonNumber(v, out, error);
        case UniValue::VSTR:  AppendCanonicalJsonString(v.get_str(), out); return true;
        case UniValue::VARR: {
            out.push_back('[');
            for (size_t i = 0; i < v.size(); ++i) {
                if (i) out.push_back(',');
                if (!AppendCanonicalJsonValue(v[i], out, error)) return false;
            }
            out.push_back(']');
            return true;
        }
        case UniValue::VOBJ: {
            out.push_back('{');
            std::vector<std::string> keys = v.getKeys();
            std::sort(keys.begin(), keys.end());
            for (size_t i = 1; i < keys.size(); ++i) {
                if (keys[i] == keys[i - 1]) { error = "duplicate object key: " + keys[i]; return false; }
            }
            for (size_t i = 0; i < keys.size(); ++i) {
                if (i) out.push_back(',');
                AppendCanonicalJsonString(keys[i], out);
                out.push_back(':');
                if (!AppendCanonicalJsonValue(v[keys[i]], out, error)) return false;
            }
            out.push_back('}');
            return true;
        }
    }
    error = "unsupported UniValue type in canonical band JSON";
    return false;
}

std::optional<std::vector<unsigned char>> CanonicalizeIcuBandJson(const UniValue& v, std::string& error) {
    std::string out;
    if (!AppendCanonicalJsonValue(v, out, error)) return std::nullopt;
    return std::vector<unsigned char>(out.begin(), out.end());
}

std::optional<UniValue> ExtractInlineIcuContext(const std::string& normalized_canonical_text,
                                                bool& present, std::string& error) {
    present = false;
    error.clear();  // "no block" and valid-block returns must leave error empty; only fault paths set it
    const std::string B = ICU_CONTEXT_BLOCK_BEGIN;
    const std::string E = ICU_CONTEXT_BLOCK_END;

    const size_t b = normalized_canonical_text.find(B);
    if (b == std::string::npos) return std::nullopt;  // no inline context -- not an error
    present = true;
    if (normalized_canonical_text.find(B, b + B.size()) != std::string::npos) {
        error = "multiple ICU context begin delimiters"; return std::nullopt;
    }
    const size_t e = normalized_canonical_text.find(E, b + B.size());
    if (e == std::string::npos) { error = "ICU context end delimiter missing"; return std::nullopt; }
    if (normalized_canonical_text.find(E, e + E.size()) != std::string::npos) {
        error = "multiple ICU context end delimiters"; return std::nullopt;
    }

    // The JSON sits between the begin and end delimiters; trim surrounding CR/LF/space/tab.
    size_t js = b + B.size();
    size_t je = e;
    while (js < je && (normalized_canonical_text[js] == '\r' || normalized_canonical_text[js] == '\n' ||
                       normalized_canonical_text[js] == ' '  || normalized_canonical_text[js] == '\t')) ++js;
    while (je > js && (normalized_canonical_text[je - 1] == '\r' || normalized_canonical_text[je - 1] == '\n' ||
                       normalized_canonical_text[je - 1] == ' '  || normalized_canonical_text[je - 1] == '\t')) --je;

    const std::string json = normalized_canonical_text.substr(js, je - js);
    UniValue meta;
    if (!meta.read(json) || !meta.isObject()) { error = "ICU context block is not a JSON object"; return std::nullopt; }

    std::string verr;
    if (!ValidateIcuContext(meta, normalized_canonical_text, verr, IcuContextBinding::InlineV2)) {
        error = "ICU context invalid: " + verr; return std::nullopt;
    }

    // Enforce the canonical single-line serialization contract on read: the embedded slice MUST be
    // byte-identical to SerializeCanonicalIcuContext(parsed). This rejects key-reordered, padded, or
    // otherwise non-canonical encodings of an otherwise-valid map, so there is exactly one accepted
    // byte form per context.
    std::string canon_err;
    auto canonical = SerializeCanonicalIcuContext(meta, canon_err);
    if (!canonical) { error = "ICU context re-serialization failed: " + canon_err; return std::nullopt; }
    if (*canonical != json) { error = "ICU context block is not in canonical serialization"; return std::nullopt; }

    return meta;
}

bool HasInlineIcuContextMarker(const std::vector<unsigned char>& metadata) {
    if (metadata.empty()) return false;
    const std::string s(metadata.begin(), metadata.end());
    UniValue m;
    if (!m.read(s) || !m.isObject()) return false;
    return m.exists("icu_ctx") && m["icu_ctx"].isStr() && m["icu_ctx"].get_str() == "inline";
}

bool VerifyIcuPlainCommit(const CanonicalIcuPayload& payload, const uint256& declared_plain_commit) {
    const std::string text(payload.canonical_text.begin(), payload.canonical_text.end());
    auto norm = NormalizeCanonicalText(text);
    if (!norm) return false;
    CSHA256 hasher;
    uint256 got;
    hasher.Write(reinterpret_cast<const unsigned char*>(norm->data()), norm->size());
    hasher.Finalize(got.begin());
    return got == declared_plain_commit;
}

std::optional<std::string> ComposeCanonicalTextWithInlineContext(
    const std::string& human_body,
    const std::vector<std::string>& clause_texts,
    const std::string& acceptance,
    UniValue& out_context,
    std::vector<std::string>& out_body_keys,
    std::string& error)
{
    if (acceptance != "required" && acceptance != "optional") {
        error = "acceptance must be \"required\" or \"optional\""; return std::nullopt;
    }
    if (clause_texts.empty()) { error = "at least one clause is required"; return std::nullopt; }

    auto norm_body = NormalizeCanonicalText(human_body);
    if (!norm_body) { error = "human body contains disallowed code points"; return std::nullopt; }
    if (norm_body->find(ICU_CONTEXT_BLOCK_BEGIN) != std::string::npos ||
        norm_body->find(ICU_CONTEXT_BLOCK_END) != std::string::npos) {
        error = "human body must not contain the ICU context delimiters"; return std::nullopt;
    }

    UniValue bodies(UniValue::VOBJ);
    out_body_keys.clear();
    std::set<std::string> seen;
    for (const std::string& raw : clause_texts) {
        auto nv = NormalizeCanonicalText(raw);
        if (!nv) { error = "clause body contains disallowed code points"; return std::nullopt; }
        if (nv->empty()) { error = "clause body is empty after normalization"; return std::nullopt; }
        if (nv->find(ICU_CONTEXT_BLOCK_BEGIN) != std::string::npos ||
            nv->find(ICU_CONTEXT_BLOCK_END) != std::string::npos) {
            error = "clause body must not contain the ICU context delimiters"; return std::nullopt;
        }
        const std::string key = Sha256HexLower(*nv);
        if (!seen.insert(key).second) { error = "duplicate clause body"; return std::nullopt; }
        bodies.pushKV(key, *nv);
        out_body_keys.push_back(key);
    }

    out_context = UniValue(UniValue::VOBJ);
    out_context.pushKV("spec", ICU_CONTEXT_SPEC_V1);
    out_context.pushKV("parse_version", 1);
    out_context.pushKV("acceptance", acceptance);
    out_context.pushKV("bodies", bodies);

    // Defensive: validate the object we just built (InlineV2 -- no substring requirement).
    std::string verr;
    if (!ValidateIcuContext(out_context, /*normalized_canonical=*/std::string(), verr, IcuContextBinding::InlineV2)) {
        error = "internal: composed context failed validation: " + verr; return std::nullopt;
    }

    auto json = SerializeCanonicalIcuContext(out_context, error);
    if (!json) return std::nullopt;

    // human body, blank line, delimited block. We emit LF; BuildCanonicalIcuPayload's
    // NormalizeCanonicalText converts every line ending to CRLF before hashing.
    std::string assembled = *norm_body;
    assembled += "\n\n";
    assembled += ICU_CONTEXT_BLOCK_BEGIN;
    assembled += "\n";
    assembled += *json;
    assembled += "\n";
    assembled += ICU_CONTEXT_BLOCK_END;
    assembled += "\n";
    return assembled;
}

std::optional<CanonicalIcuPayload> ParseCanonicalIcuPayload(const std::vector<unsigned char>& raw_bytes) {
    return CanonicalIcuPayload::Deserialize(raw_bytes);
}

// New version that returns IcuStorageEntry with metadata
bool BuildCanonicalIcuPayload(
    const std::string& canonical_text_str,
    const UniValue& witness_obj,
    uint8_t visibility,
    const std::array<unsigned char, 32>& dek,
    bool use_compression,
    uint256& icu_plain_commit,
    uint256& icu_ctxt_commit,
    std::array<unsigned char, 16>& kdf_salt,
    IcuStorageEntry& storage_entry,
    const std::vector<unsigned char>& metadata
) {
    // Step 1: Normalize canonical text
    auto normalized_opt = NormalizeCanonicalText(canonical_text_str);
    if (!normalized_opt) {
        return false;
    }
    const std::string& normalized_text = *normalized_opt;

    // Option A fail-closed gate: if canonical_text carries an embedded TSC-ICU-CONTEXT-1 block, it
    // MUST parse and validate (InlineV2) before we commit. Same total-or-refuse discipline as the
    // legacy metadata-context path below, but for the inline (text-committed) map.
    {
        bool ctx_present = false;
        std::string ctx_err;
        auto inline_ctx = ExtractInlineIcuContext(normalized_text, ctx_present, ctx_err);
        if (ctx_present && !inline_ctx) {
            LogPrintf("BuildCanonicalIcuPayload: invalid inline ICU context: %s\n", ctx_err);
            return false;
        }
    }

    // Step 2: Compute canonical_hash = SHA256(canonical_text)
    CSHA256 hasher;
    hasher.Write((const unsigned char*)normalized_text.data(), normalized_text.size());
    uint256 canonical_hash;
    hasher.Finalize(canonical_hash.begin());

    // Set icu_plain_commit (plaintext commitment)
    icu_plain_commit = canonical_hash;

    // Step 3: Build witness bundle
    UniValue witness_copy = witness_obj;

    // Insert canonical_hash if not present
    if (witness_copy.isObject() && !witness_copy.exists("canonical_hash")) {
        witness_copy.pushKV("canonical_hash", canonical_hash.ToString());
    }

    // Serialize witness bundle (JSON string to bytes)
    std::string witness_str = witness_copy.write(0, 0);  // Compact JSON
    std::vector<unsigned char> witness_bytes(witness_str.begin(), witness_str.end());

    // Compute witness_hash = SHA256(witness_bundle)
    CSHA256 witness_hasher;
    witness_hasher.Write(witness_bytes.data(), witness_bytes.size());
    uint256 witness_hash;
    witness_hasher.Finalize(witness_hash.begin());

    // Step 4: Build CanonicalIcuPayload structure
    CanonicalIcuPayload payload;
    payload.version = 1;
    payload.visibility = visibility;
    payload.canonical_text = std::vector<unsigned char>(normalized_text.begin(), normalized_text.end());
    payload.witness_bundle = witness_bytes;
    payload.metadata = metadata;  // sealed by icu_ctxt_commit below; does NOT affect canonical_hash

    // If metadata carries a TSC-ICU-CONTEXT-1 map, it MUST validate against the normalized
    // canonical text before we commit it (total-or-refuse: never commit an invalid context).
    if (!metadata.empty()) {
        UniValue meta_json;
        const std::string meta_str(metadata.begin(), metadata.end());
        if (meta_json.read(meta_str) && meta_json.isObject() &&
            meta_json.exists("spec") && meta_json["spec"].isStr() &&
            meta_json["spec"].get_str() == ICU_CONTEXT_SPEC_V1) {
            std::string ctx_err;
            if (!ValidateIcuContext(meta_json, normalized_text, ctx_err)) {
                LogPrintf("BuildCanonicalIcuPayload: invalid ICU context map: %s\n", ctx_err);
                return false;
            }
        }
    }

    // Set compression and encryption modes BEFORE serialization
    uint8_t encryption_mode, compression;
    compression = use_compression ? 1 : 0;
    if (visibility == 0) {
        encryption_mode = 0;
        payload.compression = compression;
        payload.encryption_mode = 0;
    } else {
        encryption_mode = 1;  // ChaCha20-Poly1305
        payload.compression = compression;
        payload.encryption_mode = encryption_mode;
    }

    // Step 5: Serialize payload
    std::vector<unsigned char> plaintext = payload.Serialize();
    std::vector<unsigned char> icu_cipher;

    if (visibility == 0) {
        // Public: apply compression if requested (no encryption)
        kdf_salt.fill(0);  // Zero-filled for public assets
        if (use_compression) {
            auto compressed = CompressZstd(plaintext, 3 /* level */);
            if (!compressed) {
                return false; // Compression failed
            }
            icu_cipher = *compressed;
        } else {
            icu_cipher = plaintext;
        }
    } else {
        // Holder-only: encrypt with optional compression

        // Derive deterministic but nonce-safe kdf_salt from both DEK and plaintext commitment
        // HKDF(dek, "ICU/v1" || icu_plain_commit) ensures unique nonces even if DEK is reused
        // This guarantees: same DEK + same plaintext = same ciphertext (deterministic)
        // but different plaintext = different nonce (safe AEAD)
        CHMAC_SHA256 nonce_deriver(dek.data(), dek.size());
        const unsigned char context[] = "ICU/v1";
        nonce_deriver.Write(context, sizeof(context) - 1);
        nonce_deriver.Write(icu_plain_commit.begin(), icu_plain_commit.size());
        std::array<unsigned char, 32> nonce_material;
        nonce_deriver.Finalize(nonce_material.data());

        // Copy first 16 bytes to kdf_salt (consensus-visible parameter)
        std::copy_n(nonce_material.begin(), 16, kdf_salt.begin());

        // Step 5a: Compress if requested (zstd is deterministic)
        std::vector<unsigned char> data_to_encrypt = plaintext;
        if (use_compression) {
            auto compressed = CompressZstd(plaintext, 3 /* level */);
            if (!compressed) {
                return false; // Compression failed
            }
            data_to_encrypt = *compressed;
        }

        // Step 5b: Derive nonce from kdf_salt (first 12 bytes)
        std::array<unsigned char, 12> nonce;
        std::copy_n(kdf_salt.begin(), 12, nonce.begin());

        // Step 5c: Encrypt with ChaCha20-Poly1305 using DEK directly
        auto encrypted = EncryptChaCha20Poly1305(data_to_encrypt, dek, nonce);
        if (!encrypted) {
            return false; // Encryption failed
        }

        icu_cipher = *encrypted;
    }

    // Step 6: Compute ciphertext commitment
    CSHA256 cipher_hasher;
    cipher_hasher.Write(icu_cipher.data(), icu_cipher.size());
    cipher_hasher.Finalize(icu_ctxt_commit.begin());

    // Step 7: Populate IcuStorageEntry with metadata
    storage_entry.icu_cipher = icu_cipher;
    storage_entry.compression = compression;
    storage_entry.encryption_mode = encryption_mode;
    storage_entry.visibility = visibility;
    storage_entry.canonical_hash = canonical_hash;
    storage_entry.witness_hash = witness_hash;

    return true;
}

// Legacy version that just returns icu_cipher
bool BuildCanonicalIcuPayload(
    const std::string& canonical_text_str,
    const UniValue& witness_obj,
    uint8_t visibility,
    const std::array<unsigned char, 32>& dek,
    bool use_compression,
    uint256& icu_plain_commit,
    uint256& icu_ctxt_commit,
    std::array<unsigned char, 16>& kdf_salt,
    std::vector<unsigned char>& icu_cipher,
    const std::vector<unsigned char>& metadata
) {
    // Call the new version and extract icu_cipher
    IcuStorageEntry storage_entry;
    bool result = BuildCanonicalIcuPayload(
        canonical_text_str,
        witness_obj,
        visibility,
        dek,
        use_compression,
        icu_plain_commit,
        icu_ctxt_commit,
        kdf_salt,
        storage_entry,
        metadata
    );
    icu_cipher = storage_entry.icu_cipher;
    return result;
}

// ============================================================================
// Compression Functions
// ============================================================================

std::optional<std::vector<unsigned char>> CompressZstd(const std::vector<unsigned char>& input, int level) {
    if (input.empty()) {
        return std::vector<unsigned char>();
    }

    // Estimate compressed size (worst case)
    size_t max_compressed_size = ZSTD_compressBound(input.size());
    std::vector<unsigned char> compressed(max_compressed_size);

    // Compress
    size_t compressed_size = ZSTD_compress(
        compressed.data(),
        compressed.size(),
        input.data(),
        input.size(),
        level
    );

    if (ZSTD_isError(compressed_size)) {
        return std::nullopt;
    }

    compressed.resize(compressed_size);
    return compressed;
}

std::optional<std::vector<unsigned char>> DecompressZstd(const std::vector<unsigned char>& input) {
    if (input.empty()) {
        return std::vector<unsigned char>();
    }

    // Get decompressed size
    unsigned long long decompressed_size = ZSTD_getFrameContentSize(input.data(), input.size());

    if (decompressed_size == ZSTD_CONTENTSIZE_ERROR || decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        return std::nullopt;
    }

    // Sanity check: limit to 100MB
    if (decompressed_size > 100 * 1024 * 1024) {
        return std::nullopt;
    }

    std::vector<unsigned char> decompressed(decompressed_size);

    // Decompress
    size_t result = ZSTD_decompress(
        decompressed.data(),
        decompressed.size(),
        input.data(),
        input.size()
    );

    if (ZSTD_isError(result)) {
        return std::nullopt;
    }

    return decompressed;
}

// ============================================================================
// Encryption Functions
// ============================================================================

std::optional<std::vector<unsigned char>> EncryptChaCha20Poly1305(
    const std::vector<unsigned char>& plaintext,
    const std::array<unsigned char, 32>& key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad
) {
    // Convert to std::byte for Bitcoin Core's crypto API
    std::array<std::byte, 32> key_bytes;
    for (size_t i = 0; i < 32; ++i) {
        key_bytes[i] = static_cast<std::byte>(key[i]);
    }

    // Construct Nonce96 (pair<uint32_t, uint64_t>) from 12-byte array
    // First 4 bytes = uint32_t (LE), next 8 bytes = uint64_t (LE)
    uint32_t nonce_first = nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24);
    uint64_t nonce_second = static_cast<uint64_t>(nonce[4]) |
                           (static_cast<uint64_t>(nonce[5]) << 8) |
                           (static_cast<uint64_t>(nonce[6]) << 16) |
                           (static_cast<uint64_t>(nonce[7]) << 24) |
                           (static_cast<uint64_t>(nonce[8]) << 32) |
                           (static_cast<uint64_t>(nonce[9]) << 40) |
                           (static_cast<uint64_t>(nonce[10]) << 48) |
                           (static_cast<uint64_t>(nonce[11]) << 56);
    AEADChaCha20Poly1305::Nonce96 nonce96{nonce_first, nonce_second};

    // Create cipher output buffer (plaintext + 16-byte Poly1305 tag)
    std::vector<unsigned char> ciphertext(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);

    // Convert plaintext to std::byte
    std::vector<std::byte> plaintext_bytes(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext_bytes[i] = static_cast<std::byte>(plaintext[i]);
    }

    // Convert AAD to std::byte
    std::vector<std::byte> aad_bytes(aad.size());
    for (size_t i = 0; i < aad.size(); ++i) {
        aad_bytes[i] = static_cast<std::byte>(aad[i]);
    }

    // Convert cipher output to std::byte
    std::vector<std::byte> cipher_bytes(ciphertext.size());

    // Encrypt
    AEADChaCha20Poly1305 aead(key_bytes);
    aead.Encrypt(
        std::span<const std::byte>(plaintext_bytes),
        std::span<const std::byte>(aad_bytes),
        nonce96,
        std::span<std::byte>(cipher_bytes)
    );

    // Convert back to unsigned char
    for (size_t i = 0; i < cipher_bytes.size(); ++i) {
        ciphertext[i] = static_cast<unsigned char>(cipher_bytes[i]);
    }

    return ciphertext;
}

std::optional<std::vector<unsigned char>> DecryptChaCha20Poly1305(
    const std::vector<unsigned char>& ciphertext,
    const std::array<unsigned char, 32>& key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad
) {
    // Verify minimum size (tag is 16 bytes)
    if (ciphertext.size() < AEADChaCha20Poly1305::EXPANSION) {
        return std::nullopt;
    }

    // Convert to std::byte for Bitcoin Core's crypto API
    std::array<std::byte, 32> key_bytes;
    for (size_t i = 0; i < 32; ++i) {
        key_bytes[i] = static_cast<std::byte>(key[i]);
    }

    // Construct Nonce96 (pair<uint32_t, uint64_t>) from 12-byte array
    // First 4 bytes = uint32_t (LE), next 8 bytes = uint64_t (LE)
    uint32_t nonce_first = nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24);
    uint64_t nonce_second = static_cast<uint64_t>(nonce[4]) |
                           (static_cast<uint64_t>(nonce[5]) << 8) |
                           (static_cast<uint64_t>(nonce[6]) << 16) |
                           (static_cast<uint64_t>(nonce[7]) << 24) |
                           (static_cast<uint64_t>(nonce[8]) << 32) |
                           (static_cast<uint64_t>(nonce[9]) << 40) |
                           (static_cast<uint64_t>(nonce[10]) << 48) |
                           (static_cast<uint64_t>(nonce[11]) << 56);
    AEADChaCha20Poly1305::Nonce96 nonce96{nonce_first, nonce_second};

    // Convert ciphertext to std::byte
    std::vector<std::byte> cipher_bytes(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        cipher_bytes[i] = static_cast<std::byte>(ciphertext[i]);
    }

    // Convert AAD to std::byte
    std::vector<std::byte> aad_bytes(aad.size());
    for (size_t i = 0; i < aad.size(); ++i) {
        aad_bytes[i] = static_cast<std::byte>(aad[i]);
    }

    // Create plaintext output buffer
    std::vector<std::byte> plaintext_bytes(ciphertext.size() - AEADChaCha20Poly1305::EXPANSION);

    // Decrypt
    AEADChaCha20Poly1305 aead(key_bytes);
    bool success = aead.Decrypt(
        std::span<const std::byte>(cipher_bytes),
        std::span<const std::byte>(aad_bytes),
        nonce96,
        std::span<std::byte>(plaintext_bytes)
    );

    if (!success) {
        return std::nullopt; // Authentication failed
    }

    // Convert back to unsigned char
    std::vector<unsigned char> plaintext(plaintext_bytes.size());
    for (size_t i = 0; i < plaintext_bytes.size(); ++i) {
        plaintext[i] = static_cast<unsigned char>(plaintext_bytes[i]);
    }

    return plaintext;
}

// ============================================================================
// High-Level Decryption
// ============================================================================

std::optional<CanonicalIcuPayload> DecryptCanonicalIcuPayload(
    const std::vector<unsigned char>& icu_cipher,
    const std::array<unsigned char, 32>& dek,
    const std::array<unsigned char, 16>& kdf_salt,
    uint8_t encryption_mode,
    uint8_t compression
) {
    std::vector<unsigned char> plaintext = icu_cipher;

    // Step 1: Decrypt if encrypted
    if (encryption_mode == 0) {
        // No encryption
    } else if (encryption_mode == 1 || encryption_mode == 2) {
        // Derive nonce from kdf_salt (first 12 bytes)
        std::array<unsigned char, 12> nonce;
        std::copy_n(kdf_salt.begin(), 12, nonce.begin());

        // Decrypt using ChaCha20-Poly1305 with DEK directly
        auto decrypted = DecryptChaCha20Poly1305(icu_cipher, dek, nonce);
        if (!decrypted) {
            return std::nullopt; // Decryption failed (authentication tag mismatch or wrong DEK)
        }
        plaintext = *decrypted;
    } else {
        return std::nullopt;
    }

    // Step 2: Decompress if compressed
    if (compression == 0) {
        // No compression
    } else if (compression == 1) {
        auto decompressed = DecompressZstd(plaintext);
        if (!decompressed) {
            return std::nullopt; // Decompression failed
        }
        plaintext = *decompressed;
    } else {
        return std::nullopt;
    }

    // Step 3: Parse canonical structure
    return CanonicalIcuPayload::Deserialize(plaintext);
}

std::vector<unsigned char> AppendIcuChunkMetadata(
    const std::vector<unsigned char>& payload,
    const IcuChunkMetadata& metadata
) {
    std::vector<unsigned char> out(payload);
    std::array<unsigned char, ICU_CHUNK_TRAILER_SIZE> trailer{};
    std::copy(std::begin(ICU_CHUNK_TRAILER_MAGIC), std::end(ICU_CHUNK_TRAILER_MAGIC), trailer.begin());

    size_t idx = 4;
    trailer[idx++] = metadata.version;
    trailer[idx++] = metadata.compression;
    trailer[idx++] = metadata.encryption_mode;
    uint8_t flags = metadata.has_witness_hash ? 0x01 : 0x00;
    trailer[idx++] = flags;
    if (metadata.has_witness_hash) {
        std::array<unsigned char, 32> little_bytes;
        std::copy(metadata.witness_hash.begin(), metadata.witness_hash.end(), little_bytes.begin());
        std::array<unsigned char, 32> big_bytes;
        std::reverse_copy(little_bytes.begin(), little_bytes.end(), big_bytes.begin());
        std::copy(big_bytes.begin(), big_bytes.end(), trailer.begin() + idx);
    } else {
        std::fill(trailer.begin() + idx, trailer.begin() + idx + 32, 0);
    }

    out.insert(out.end(), trailer.begin(), trailer.end());
    return out;
}

bool StripIcuChunkMetadata(
    std::vector<unsigned char>& payload,
    IcuChunkMetadata& metadata
) {
    if (payload.size() < ICU_CHUNK_TRAILER_SIZE) {
        return false;
    }
    const size_t offset = payload.size() - ICU_CHUNK_TRAILER_SIZE;
    if (!std::equal(std::begin(ICU_CHUNK_TRAILER_MAGIC), std::end(ICU_CHUNK_TRAILER_MAGIC),
                    payload.begin() + offset)) {
        return false;
    }

    size_t idx = offset + 4;
    metadata.version = payload[idx++];
    if (metadata.version != 1) {
        return false;
    }
    metadata.compression = payload[idx++];
    metadata.encryption_mode = payload[idx++];
    uint8_t flags = payload[idx++];
    metadata.has_witness_hash = (flags & 0x01) != 0;
    if (metadata.has_witness_hash) {
        std::array<unsigned char, 32> big_bytes;
        std::copy(payload.begin() + idx, payload.begin() + idx + 32, big_bytes.begin());
        std::array<unsigned char, 32> little_bytes;
        std::reverse_copy(big_bytes.begin(), big_bytes.end(), little_bytes.begin());
        std::copy(little_bytes.begin(), little_bytes.end(), metadata.witness_hash.begin());
    } else {
        metadata.witness_hash.SetNull();
    }

    payload.resize(offset);
    return true;
}

} // namespace assets
