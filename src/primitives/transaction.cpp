// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <assets/asset.h>
#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/transaction_identifier.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <optional>
#include <stdexcept>

namespace {

static bool ReadCompactSizeFrom(const unsigned char*& p, const unsigned char* end, uint64_t& out_len)
{
    if (p >= end) return false;
    unsigned char ch = *p++;
    if (ch < 253) { out_len = ch; return true; }
    if (ch == 253) {
        if (end - p < 2) return false;
        out_len = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8);
        p += 2;
        if (out_len < 253) return false;
        return true;
    }
    if (ch == 254) {
        if (end - p < 4) return false;
        out_len = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24);
        p += 4;
        if (out_len < 0x10000ULL) return false;
        return true;
    }
    if (end - p < 8) return false;
    out_len =  ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
             | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
    p += 8;
    if (out_len < 0x100000000ULL) return false;
    return true;
}

static bool ParseSingleTLV(const std::vector<unsigned char>& vext, uint8_t& type, const unsigned char*& val, size_t& vlen)
{
    if (vext.size() < 2) return false;
    const unsigned char* p = vext.data();
    const unsigned char* end = vext.data() + vext.size();
    type = *p++;
    uint64_t len = 0;
    if (!ReadCompactSizeFrom(p, end, len)) return false;
    if ((size_t)(end - p) != len) return false;
    val = p;
    vlen = static_cast<size_t>(len);
    return true;
}

static std::optional<assets::AssetTag> ParseAssetTagLocal(const std::vector<unsigned char>& vext)
{
    uint8_t type; const unsigned char* val; size_t vlen;
    if (!ParseSingleTLV(vext, type, val, vlen)) return std::nullopt;
    if (type != static_cast<uint8_t>(assets::OutExtType::ASSET_TAG)) return std::nullopt;
    if (vlen < 32 + 8) return std::nullopt;
    assets::AssetTag tag{};
    std::memcpy(tag.id.begin(), val, 32);
    if (tag.id.IsNull()) return std::nullopt;
    tag.amount = ReadLE64(val + 32);
    const size_t cursor = 32 + 8;
    if (vlen >= cursor + 4 && val[cursor] != 0x02 && val[cursor] != 0x03) {
        tag.flags = ReadLE32(val + cursor);
    }
    return tag;
}

} // namespace

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    std::string ext = vExt.empty() ? std::string{} : (", outext=" + HexStr(vExt).substr(0, 30));
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30), ext);
}

bool CTxOut::HasAssetTLV() const
{
    if (vExt.empty()) return false;
    return ParseAssetTagLocal(vExt).has_value();
}

std::optional<uint256> CTxOut::AssetID() const
{
    if (auto tag = ParseAssetTagLocal(vExt)) {
        return tag->id;
    }
    return std::nullopt;
}

std::optional<uint64_t> CTxOut::AssetAmount() const
{
    if (auto tag = ParseAssetTagLocal(vExt)) {
        return tag->amount;
    }
    return std::nullopt;
}

CMutableTransaction::CMutableTransaction() : version{CTransaction::CURRENT_VERSION}, nLockTime{0} {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime} {}

Txid CMutableTransaction::GetHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

bool CTransaction::ComputeHasWitness() const
{
    return std::any_of(vin.begin(), vin.end(), [](const auto& input) {
        return !input.scriptWitness.IsNull();
    });
}

Txid CTransaction::ComputeHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

Wtxid CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return Wtxid::FromUint256(hash.ToUint256());
    }

    return Wtxid::FromUint256((HashWriter{} << TX_WITH_WITNESS(*this)).GetHash());
}

CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), version{tx.version}, nLockTime{tx.nLockTime}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(TX_WITH_WITNESS(*this));
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        version,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}

// Governance rotation: compute proposal hash binding
template <typename TxType>
uint256 ComputeRotationProposalHash(const TxType& tx)
{
    if (tx.vin.empty() || tx.vout.empty()) {
        return uint256();  // Return null hash for invalid rotation tx
    }

    // Proposal hash binds: vin[0].prevout (ICU being rotated) || vout[0].vExt (new IssuerReg)
    HashWriter hasher{};
    hasher << std::string("ROTATION/PROPOSAL");

    // Serialize vin[0].prevout
    hasher << tx.vin[0].prevout;

    // Serialize vout[0].vExt
    hasher.write(MakeByteSpan(tx.vout[0].vExt));

    return hasher.GetSHA256();
}

// Explicit instantiations for CTransaction and CMutableTransaction
template uint256 ComputeRotationProposalHash<CTransaction>(const CTransaction& tx);
template uint256 ComputeRotationProposalHash<CMutableTransaction>(const CMutableTransaction& tx);
