// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <assets/registry.h>
#include <assets/icu_payload.h>

/** Formatter for undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is compatible with older versions which expect to see
 *  the transaction version there.
 */
struct TxInUndoFormatter
{
    template<typename Stream>
    void Ser(Stream &s, const Coin& txout) {
        ::Serialize(s, VARINT(txout.nHeight * uint32_t{2} + txout.fCoinBase ));
        if (txout.nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, Using<TxOutCompression>(txout.out));
    }

    template<typename Stream>
    void Unser(Stream &s, Coin& txout) {
        uint32_t nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout.nHeight = nCode >> 1;
        txout.fCoinBase = nCode & 1;
        if (txout.nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, Using<TxOutCompression>(txout.out));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) { READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout)); }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    // Asset registry undo entries for this block
    struct RegUndoEntry {
        uint256 asset_id;
        bool had_prev{false};
        AssetRegistryEntry prev{};

        SERIALIZE_METHODS(RegUndoEntry, obj) {
            READWRITE(obj.asset_id);
            READWRITE(obj.had_prev);
            if (obj.had_prev) READWRITE(obj.prev);
        }
    };
    std::vector<RegUndoEntry> reg_undo;
    // Fee accumulator undo entries for this block
    struct FeeUndoEntry {
        uint256 asset_id;
        uint64_t delta{0};

        SERIALIZE_METHODS(FeeUndoEntry, obj) { READWRITE(obj.asset_id, obj.delta); }
    };
    std::vector<FeeUndoEntry> fee_undo;

    struct VkUndoEntry {
        uint256 vk_hash;
        bool had_prev{false};
        std::vector<unsigned char> prev_payload;

        SERIALIZE_METHODS(VkUndoEntry, obj) {
            READWRITE(obj.vk_hash, obj.had_prev, obj.prev_payload);
        }
    };
    std::vector<VkUndoEntry> vk_undo;

    struct IcuUndoEntry {
        uint256 asset_id;
        uint256 icu_ctxt_commit;
        bool had_prev{false};
        assets::IcuStorageEntry prev_payload;

        SERIALIZE_METHODS(IcuUndoEntry, obj) {
            READWRITE(obj.asset_id, obj.icu_ctxt_commit, obj.had_prev, obj.prev_payload);
        }
    };
    std::vector<IcuUndoEntry> icu_undo;

    // Scalar-feed publication undo entries (CFD_GENERALISATION.md §3.2). A publication
    // writes a per-epoch record (asset_id, feed_id, epoch) and advances the per-feed
    // head. To disconnect: erase that epoch record and restore the prior head — or
    // erase the head entirely if this publication created the feed (had_prev_head=false).
    // Produced in ConnectBlock and consumed in DisconnectBlock (Slice 1d).
    // NOTE: appending this channel bumps the on-disk undo (rev*.dat) format, exactly
    // as the earlier vk_undo / icu_undo additions did, so upgrading a node across the
    // activation requires -reindex (old undo files lack the trailing field).
    struct ScalarUndoEntry {
        uint256 asset_id;
        uint32_t feed_id{0};
        uint64_t epoch{0};
        bool had_prev_head{false};
        uint64_t prev_last_epoch{0};

        SERIALIZE_METHODS(ScalarUndoEntry, obj) {
            READWRITE(obj.asset_id, obj.feed_id, obj.epoch, obj.had_prev_head, obj.prev_last_epoch);
        }
    };
    std::vector<ScalarUndoEntry> scalar_undo;

    SERIALIZE_METHODS(CBlockUndo, obj) { READWRITE(obj.vtxundo, obj.reg_undo, obj.fee_undo, obj.vk_undo, obj.icu_undo, obj.scalar_undo); }
};

#endif // BITCOIN_UNDO_H
