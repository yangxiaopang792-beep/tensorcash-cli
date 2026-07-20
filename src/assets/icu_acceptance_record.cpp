// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/icu_acceptance_record.h>

#include <crypto/sha256.h>
#include <hash.h>                    // TaggedHash, HashWriter
#include <pubkey.h>                  // XOnlyPubKey::VerifySchnorr
#include <util/strencodings.h>       // HexStr

#include <algorithm>
#include <cstring>
#include <span>

namespace assets {

namespace {

void put_u16(std::vector<unsigned char>& v, uint16_t x) { v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF); }
void put_u32(std::vector<unsigned char>& v, uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xFF); }
void put_u64(std::vector<unsigned char>& v, uint64_t x) { for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xFF); }
void put_h(std::vector<unsigned char>& v, const uint256& h) { v.insert(v.end(), h.begin(), h.end()); }
void put_compact(std::vector<unsigned char>& v, uint64_t n) {
    if (n < 253) { v.push_back(static_cast<unsigned char>(n)); }
    else if (n <= 0xFFFF) { v.push_back(253); put_u16(v, static_cast<uint16_t>(n)); }
    else if (n <= 0xFFFFFFFF) { v.push_back(254); put_u32(v, static_cast<uint32_t>(n)); }
    else { v.push_back(255); put_u64(v, n); }
}

// Bounds-checked little-endian reader; every getter fails closed when short.
struct Rd {
    const unsigned char* p;
    const unsigned char* end;
    bool need(size_t n) const { return static_cast<size_t>(end - p) >= n; }
    bool u8(uint8_t& x) { if (!need(1)) return false; x = *p++; return true; }
    bool u16(uint16_t& x) { if (!need(2)) return false; x = static_cast<uint16_t>(p[0] | (p[1] << 8)); p += 2; return true; }
    bool u32(uint32_t& x) { if (!need(4)) return false; x = 0; for (int i = 0; i < 4; ++i) x |= static_cast<uint32_t>(p[i]) << (8 * i); p += 4; return true; }
    bool u64(uint64_t& x) { if (!need(8)) return false; x = 0; for (int i = 0; i < 8; ++i) x |= static_cast<uint64_t>(p[i]) << (8 * i); p += 8; return true; }
    bool h256(uint256& h) { if (!need(32)) return false; std::memcpy(h.begin(), p, 32); p += 32; return true; }
    bool arr32(std::array<unsigned char, 32>& a) { if (!need(32)) return false; std::memcpy(a.data(), p, 32); p += 32; return true; }
    bool compact(uint64_t& n) {
        uint8_t c; if (!u8(c)) return false;
        if (c < 253) { n = c; return true; }
        if (c == 253) { uint16_t x; if (!u16(x)) return false; n = x; return n >= 253; }
        if (c == 254) { uint32_t x; if (!u32(x)) return false; n = x; return n > 0xFFFF; }
        if (!u64(n)) return false; return n > 0xFFFFFFFF;  // reject non-canonical compact encodings
    }
    bool bytes(std::vector<unsigned char>& out, size_t n) { if (!need(n)) return false; out.assign(p, p + n); p += n; return true; }
};

} // namespace

std::vector<unsigned char> IcuAcceptanceRecord::SerializePayload() const
{
    std::vector<unsigned char> v;
    v.push_back(version);
    v.push_back(mode);
    put_u16(v, flags);
    put_h(v, asset_id);
    put_h(v, icu_plain_commit);
    put_h(v, holder_prevout_txid);
    put_u32(v, holder_prevout_vout);
    put_h(v, holder_spk_hash);
    put_u64(v, accepted_units);
    v.push_back(sig_scheme);
    put_compact(v, body_refs.size());
    for (const auto& r : body_refs) v.insert(v.end(), r.begin(), r.end());
    put_compact(v, sig.size());
    v.insert(v.end(), sig.begin(), sig.end());
    return v;
}

std::optional<IcuAcceptanceRecord> IcuAcceptanceRecord::ParsePayload(const std::vector<unsigned char>& payload)
{
    Rd rd{payload.data(), payload.data() + payload.size()};
    IcuAcceptanceRecord r;
    if (!rd.u8(r.version) || r.version != ICU_ACCEPTANCE_RECORD_VERSION) return std::nullopt;
    if (!rd.u8(r.mode)) return std::nullopt;
    if (!rd.u16(r.flags)) return std::nullopt;
    if (!rd.h256(r.asset_id) || !rd.h256(r.icu_plain_commit) || !rd.h256(r.holder_prevout_txid)) return std::nullopt;
    if (!rd.u32(r.holder_prevout_vout)) return std::nullopt;
    if (!rd.h256(r.holder_spk_hash)) return std::nullopt;
    if (!rd.u64(r.accepted_units)) return std::nullopt;
    if (!rd.u8(r.sig_scheme)) return std::nullopt;
    uint64_t nrefs = 0;
    if (!rd.compact(nrefs) || nrefs > 4096) return std::nullopt;  // sanity bound
    r.body_refs.resize(nrefs);
    for (uint64_t i = 0; i < nrefs; ++i) if (!rd.arr32(r.body_refs[i])) return std::nullopt;
    uint64_t siglen = 0;
    if (!rd.compact(siglen) || siglen > 65536) return std::nullopt;
    if (!rd.bytes(r.sig, static_cast<size_t>(siglen))) return std::nullopt;
    if (rd.p != rd.end) return std::nullopt;  // no trailing bytes (fail-closed)

    // Semantic validation: a structurally-parseable-but-nonsensical record must NOT be treated as valid
    // (consensus accepts a 0x40 vExt iff this returns a value, so it must reject garbage).
    std::string verr;
    if (!ValidateIcuAcceptanceRecord(r, verr)) return std::nullopt;
    return r;
}

bool ValidateIcuAcceptanceRecord(const IcuAcceptanceRecord& rec, std::string& reason)
{
    if (rec.version != ICU_ACCEPTANCE_RECORD_VERSION) { reason = "unsupported record version"; return false; }
    if (rec.mode != 1 && rec.mode != 2) { reason = "mode must be acknowledge(1) or return(2)"; return false; }
    if (rec.flags != 0) { reason = "reserved flags must be zero"; return false; }
    if (rec.asset_id.IsNull() || rec.icu_plain_commit.IsNull() ||
        rec.holder_prevout_txid.IsNull() || rec.holder_spk_hash.IsNull()) {
        reason = "asset_id / icu_plain_commit / holder prevout / holder spk hash must be non-null";
        return false;
    }
    if (rec.accepted_units == 0) { reason = "accepted_units must be > 0"; return false; }

    // body_refs must be strictly ascending (sorted AND unique) for a single canonical encoding.
    for (size_t i = 1; i < rec.body_refs.size(); ++i) {
        if (!(rec.body_refs[i - 1] < rec.body_refs[i])) { reason = "body_refs must be sorted and unique"; return false; }
    }
    // RETURN relinquishes the asset (attributed by the spend); it does not affirm sub-bodies.
    if (rec.mode == 2 && !rec.body_refs.empty()) { reason = "return must not carry body_refs"; return false; }

    // Mode/scheme coupling: ACKNOWLEDGE is an affirmative attestation and MUST carry a signature;
    // RETURN is attributed by the asset-input spend and MUST NOT carry a message signature.
    const auto scheme = static_cast<IcuAcceptSigScheme>(rec.sig_scheme);
    if (rec.mode == 1 && scheme == IcuAcceptSigScheme::NONE) { reason = "acknowledge must carry a signature"; return false; }
    if (rec.mode == 2 && scheme != IcuAcceptSigScheme::NONE) { reason = "return must not carry a message signature"; return false; }

    switch (scheme) {
    case IcuAcceptSigScheme::NONE:
        if (!rec.sig.empty()) { reason = "scheme NONE must carry no signature"; return false; }
        break;
    case IcuAcceptSigScheme::SECP_SCHNORR_RAW:
        // Raw BIP-340 Schnorr over a domain-separated record-message hash (NOT BIP-322). 64 bytes exact.
        if (rec.sig.size() != 64) { reason = "raw Schnorr signature must be 64 bytes"; return false; }
        break;
    case IcuAcceptSigScheme::SECP_BIP322_HASH:
        if (rec.sig.size() != 32) { reason = "bip322_hash commitment must be 32 bytes"; return false; }
        break;
    default:
        reason = "unknown sig_scheme";
        return false;
    }
    reason.clear();
    return true;
}

std::vector<unsigned char> BuildIcuAcceptanceTLV(const IcuAcceptanceRecord& rec)
{
    const std::vector<unsigned char> payload = rec.SerializePayload();
    std::vector<unsigned char> tlv;
    tlv.push_back(ICU_ACCEPTANCE_TLV_TYPE);
    put_compact(tlv, payload.size());
    tlv.insert(tlv.end(), payload.begin(), payload.end());
    return tlv;
}

std::optional<IcuAcceptanceRecord> ParseIcuAcceptanceTLV(const std::vector<unsigned char>& vext)
{
    if (vext.size() < 2 || vext[0] != ICU_ACCEPTANCE_TLV_TYPE) return std::nullopt;
    Rd rd{vext.data() + 1, vext.data() + vext.size()};
    uint64_t len = 0;
    if (!rd.compact(len)) return std::nullopt;
    if (static_cast<size_t>(rd.end - rd.p) != len) return std::nullopt;
    return IcuAcceptanceRecord::ParsePayload(std::vector<unsigned char>(rd.p, rd.p + len));
}

std::string IcuAcceptanceRecordSigningMessage(const IcuAcceptanceRecord& rec)
{
    // Bind EVERY record field except the signature. The off-chain ACCEPT-3 message bound only
    // asset/mode/doc/address/body_refs; here we additionally bind the holder prevout, spk hash,
    // accepted_units and sig_scheme, so a signature commits to THIS record and cannot be lifted.
    std::string m = "TSC-ICU-ACCEPTANCE-RECORD-1";
    m += "|v" + std::to_string(static_cast<unsigned>(rec.version));
    // Encode mode NUMERICALLY (not via IcuAcceptanceModeName, which maps any non-ACK value to "return"):
    // the signing path must not silently fold an out-of-range mode onto a valid label.
    m += "|mode=" + std::to_string(static_cast<unsigned>(rec.mode));
    m += "|flags=" + std::to_string(static_cast<unsigned>(rec.flags));
    m += "|asset=" + rec.asset_id.GetHex();
    m += "|doc=" + rec.icu_plain_commit.GetHex();
    m += "|prevout=" + rec.holder_prevout_txid.GetHex() + ":" + std::to_string(rec.holder_prevout_vout);
    m += "|spk=" + rec.holder_spk_hash.GetHex();
    m += "|units=" + std::to_string(rec.accepted_units);
    m += "|scheme=" + std::to_string(static_cast<unsigned>(rec.sig_scheme));
    m += "|bodies=";
    for (size_t i = 0; i < rec.body_refs.size(); ++i) {
        if (i) m += ",";
        m += HexStr(rec.body_refs[i]);  // lowercase raw-digest hex
    }
    return m;
}

uint256 IcuAcceptanceRecordSigningHash(const IcuAcceptanceRecord& rec)
{
    const std::string msg = IcuAcceptanceRecordSigningMessage(rec);
    HashWriter hasher = TaggedHash("TSC-ICU-ACCEPTANCE-RECORD-1");
    hasher.write(std::as_bytes(std::span<const char>(msg.data(), msg.size())));
    return hasher.GetSHA256();
}

bool VerifyIcuAcceptanceRecordSchnorr(const IcuAcceptanceRecord& rec, const XOnlyPubKey& output_key)
{
    if (rec.sig_scheme != static_cast<uint8_t>(IcuAcceptSigScheme::SECP_SCHNORR_RAW)) return false;
    if (rec.sig.size() != 64) return false;
    return output_key.VerifySchnorr(IcuAcceptanceRecordSigningHash(rec), rec.sig);
}

bool CheckIcuBodyRefsAgainstContext(const std::vector<std::array<unsigned char, 32>>& body_refs,
                                    bool has_context, const std::set<std::string>& designated_hex,
                                    bool required, std::string& reason)
{
    std::set<std::string> refs;
    for (const auto& r : body_refs) refs.insert(HexStr(r));  // lowercase raw-digest hex
    if (!has_context) {
        if (!refs.empty()) { reason = "asset has no committed context; body_refs are not applicable"; return false; }
        reason.clear();
        return true;
    }
    for (const auto& r : refs) {
        if (!designated_hex.count(r)) { reason = "body_ref " + r + " is not a designated clause in the committed context"; return false; }
    }
    if (required && refs.size() != designated_hex.size()) {
        reason = "committed context is 'required' but not all designated clauses are affirmed";
        return false;
    }
    reason.clear();
    return true;
}

bool VerifyIcuAcceptanceCommit(const IcuAcceptanceRecord& rec, const std::vector<unsigned char>& revealed_proof)
{
    if (rec.sig_scheme != static_cast<uint8_t>(IcuAcceptSigScheme::SECP_BIP322_HASH)) return false;
    if (rec.sig.size() != CSHA256::OUTPUT_SIZE) return false;
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(revealed_proof.data(), revealed_proof.size()).Finalize(digest);
    return std::equal(rec.sig.begin(), rec.sig.end(), digest);
}

uint256 IcuHolderSpkHash(const CScript& script)
{
    uint256 result;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(script.data()), script.size())
        .Finalize(result.begin());
    return result;
}

std::optional<XOnlyPubKey> ExtractTaprootOutputKeyFromSpk(const CScript& spk, TxoutType& type)
{
    std::vector<std::vector<unsigned char>> solutions;
    type = Solver(spk, solutions);
    if ((type != TxoutType::WITNESS_V1_TAPROOT && type != TxoutType::WITNESS_V2_TAPROOT) ||
        solutions.empty() || solutions[0].size() != 32) {
        return std::nullopt;
    }
    return XOnlyPubKey(solutions[0]);
}

} // namespace assets
