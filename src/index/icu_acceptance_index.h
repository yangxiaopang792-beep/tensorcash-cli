// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_ICU_ACCEPTANCE_INDEX_H
#define BITCOIN_INDEX_ICU_ACCEPTANCE_INDEX_H

#include <index/base.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <vector>

static constexpr bool DEFAULT_ICU_ACCEPTANCE_INDEX{false};

/// On-chain location of one ICU acceptance (0x40) record. Candidate-only: the caller must verify it.
struct IcuAcceptanceLoc {
    int height{0};
    uint256 txid;
    uint32_t vout{0};
    uint256 asset_id;
};

/**
 * Indexes on-chain ICU acceptance records (the 0x40 ICU_ACCEPTANCE vExt) by asset_id, so
 * icu.acceptance.record.list can enumerate an asset's candidate records without a full block scan.
 *
 * The index is a candidate LOCATOR, not a verifier: it records (asset_id, height, txid, vout) for every
 * structurally-parseable 0x40 record it sees. Entries from reorged-out blocks are left in place (no
 * CustomRewind, like txindex) -- they are harmless because list runs the full verifier, which rejects any
 * record not mined in the active chain. The verifier remains the single source of truth.
 */
class IcuAcceptanceIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    bool AllowPrune() const override { return false; }  // needs full block data to scan outputs

protected:
    bool CustomAppend(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;

public:
    explicit IcuAcceptanceIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);
    virtual ~IcuAcceptanceIndex() override;

    /// Enumerate all indexed record locations for an asset, ascending by (height, txid, vout).
    bool FindByAsset(const uint256& asset_id, std::vector<IcuAcceptanceLoc>& out) const;
};

/// The global ICU acceptance index. May be null (only created with -icuacceptanceindex).
extern std::unique_ptr<IcuAcceptanceIndex> g_icu_acceptance_index;

#endif // BITCOIN_INDEX_ICU_ACCEPTANCE_INDEX_H
