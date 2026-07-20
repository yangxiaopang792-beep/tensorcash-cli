// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include <prevector.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>

/**
 * This saves us from making many heap allocations when serializing
 * and deserializing compressed scripts.
 *
 * This prevector size is determined by the largest .resize() in the
 * CompressScript function. The largest compressed script format is a
 * compressed public key, which is 33 bytes.
 */
using CompressedScript = prevector<33, unsigned char>;


bool CompressScript(const CScript& script, CompressedScript& out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const CompressedScript& in);

/**
 * Compress amount.
 *
 * nAmount is of type uint64_t and thus cannot be negative. If you're passing in
 * a CAmount (int64_t), make sure to properly handle the case where the amount
 * is negative before calling CompressAmount(...).
 *
 * @pre Function defined only for 0 <= nAmount <= MAX_MONEY.
 */
uint64_t CompressAmount(uint64_t nAmount);

uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
struct ScriptCompression
{
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new version for
     * transactions, in which case this value becomes dependent on version
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    template<typename Stream>
    void Ser(Stream &s, const CScript& script) {
        CompressedScript compr;
        if (CompressScript(script, compr)) {
            s << std::span{compr};
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << std::span{script};
    }

    template<typename Stream>
    void Unser(Stream &s, CScript& script) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            CompressedScript vch(GetSpecialScriptSize(nSize), 0x00);
            s >> std::span{vch};
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> std::span{script};
        }
    }
};

struct AmountCompression
{
    template<typename Stream, typename I> void Ser(Stream& s, I val)
    {
        s << VARINT(CompressAmount(val));
    }
    template<typename Stream, typename I> void Unser(Stream& s, I& val)
    {
        uint64_t v;
        s >> VARINT(v);
        val = DecompressAmount(v);
    }
};

/** wrapper for CTxOut that provides a more compact serialization */
struct TxOutCompression
{
    template <typename Stream>
    inline void Ser(Stream& s, const CTxOut& obj)
    {
        s << Using<AmountCompression>(obj.nValue);
        s << Using<ScriptCompression>(obj.scriptPubKey);
        WriteCompactSize(s, obj.vExt.size());
        if (!obj.vExt.empty()) s.write(MakeByteSpan(obj.vExt));
    }

    template <typename Stream>
    inline void Unser(Stream& s, CTxOut& obj)
    {
        s >> Using<AmountCompression>(obj.nValue);
        s >> Using<ScriptCompression>(obj.scriptPubKey);
        // Backward compatibility: legacy encodings do not include vExt.
        // If there is no more data available, treat as legacy and set empty vExt.
        if constexpr (requires { s.empty(); }) {
            if (s.empty()) {
                obj.vExt.clear();
                return;
            }
        }

        // Attempt to read the extension length. If this fails due to EOF,
        // treat as legacy empty vExt. If it succeeds but exceeds bounds,
        // propagate failure to the caller.
        size_t ext_sz = 0;
        try {
            ext_sz = ReadCompactSize(s);
        } catch (const std::ios_base::failure&) {
            obj.vExt.clear();
            return;
        }

        if (ext_sz > MAX_OUEXT_SIZE_PER_OUTPUT) {
            throw std::ios_base::failure("compressed output extension too large");
        }

        obj.vExt.resize(ext_sz);
        if (ext_sz) {
            // Reading the declared payload must succeed; otherwise raise failure.
            s.read(MakeWritableByteSpan(obj.vExt));
        }
    }
};

#endif // BITCOIN_COMPRESSOR_H
