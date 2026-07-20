// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SCALAR_CFD_SNAPSHOT_H
#define BITCOIN_CONSENSUS_SCALAR_CFD_SNAPSHOT_H

#include <consensus/scalar_cfd.h>      // ResolvedScalar, ResolveScalarFixing, ScalarRecord (via registry.h)
#include <consensus/scalar_cfd_leaf.h> // ScalarCfdLeaf, ScalarCfdSourceType
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <tuple>

//! The immutable resolved-scalar snapshot that OP_SCALAR_CFD_SETTLE folds from
//! (CFD_GENERALISATION.md §3.4). The covenant runs on parallel CScriptCheck worker threads that
//! must NOT read the live coins view, so the effective scalar for every settlement input is
//! resolved ONCE, single-threaded, in CheckInputScripts (burial + the deadline/fallback rule
//! already applied) and frozen here; the opcode reads only this map. This header is the pure,
//! reader-injected core (no chain/cache access), so it is identical in block validation and
//! mempool and unit-testable in isolation.

//! Reader of a published scalar record: (underlying_asset_id, feed_id, scalar_epoch) -> record or
//! nullopt. Injected so the builder does no chain/cache access itself.
using ScalarReader = std::function<std::optional<ScalarRecord>(const uint256&, uint32_t, uint64_t)>;

struct ScalarCollateralPolicy; // defined below

//! Reader of a collateral asset's settlement-relevant policy: collateral_asset_id -> policy or
//! nullopt (unknown asset). Injected like ScalarReader so the snapshot build does the registry read
//! single-threaded and the opcode never touches the live view (§5.1).
using CollateralPolicyReader = std::function<std::optional<ScalarCollateralPolicy>(const uint256&)>;

//! The committed coordinates a settlement leaf folds its scalar from. The opcode rebuilds this key
//! from its on-stack operands and looks it up; a miss is fail-closed (the opcode fails).
struct ScalarFixingKey {
    uint8_t  source_type{0};
    uint256  underlying_asset_id;
    uint32_t feed_id{0};
    uint64_t fixing_ref{0};

    friend bool operator<(const ScalarFixingKey& a, const ScalarFixingKey& b)
    {
        return std::tie(a.source_type, a.underlying_asset_id, a.feed_id, a.fixing_ref)
             < std::tie(b.source_type, b.underlying_asset_id, b.feed_id, b.fixing_ref);
    }
};

//! The collateral asset's settlement-relevant policy fields, resolved ONCE single-threaded (a
//! registry read is forbidden on worker threads, exactly like the scalar fixing) and frozen here
//! for the non-native collateral branch of OP_SCALAR_CFD_SETTLE (CFD_GENERALISATION.md §5.1). The
//! opcode applies the GATE (§2.3 step 4) over these raw fields: it requires `collateral_safe`
//! AND `kyc_flags==0` AND `tfr_flags==0` AND `!(icu_flags & WRAP_REQUIRED)`. Storing the raw
//! fields (not a pre-computed verdict) keeps the gate logic in the interpreter where the error
//! vocabulary lives, and lets the gate evolve without re-resolving.
struct ScalarCollateralPolicy {
    bool     collateral_safe{false}; //!< the new immutable COLLATERAL_SAFE profile bit (§5.1)
    uint32_t kyc_flags{0};
    uint32_t tfr_flags{0};
    uint32_t icu_flags{0};           //!< WRAP_REQUIRED (0x0001) is the bit the gate rejects
};

//! Immutable (post-build) snapshot the opcode folds from. Two parallel maps, both frozen after the
//! single-threaded build: (1) committed key -> effective scalar; (2) collateral asset_id -> policy.
//! Both `Get*` return nullopt for an absent key, which the opcode treats as a hard fail — a leaf
//! the pre-scan could not parse/resolve, or a collateral asset whose policy was not resolved, never
//! settles (detection over-approximates, resolution under-approximates; both fail safe, §3.4/§5.1).
class ScalarFixingSnapshot {
public:
    void Add(const ScalarFixingKey& key, const ResolvedScalar& resolved) { m_map[key] = resolved; }

    std::optional<ResolvedScalar> Get(const ScalarFixingKey& key) const
    {
        const auto it = m_map.find(key);
        if (it == m_map.end()) return std::nullopt;
        return it->second;
    }

    //! Stage a collateral asset's resolved policy. Idempotent overwrite (the build resolves each
    //! collateral asset once; a re-resolution must be identical by construction).
    void AddCollateralPolicy(const uint256& collateral_asset_id, const ScalarCollateralPolicy& policy)
    {
        m_collateral[collateral_asset_id] = policy;
    }

    //! Resolved policy for a collateral asset, or nullopt (fail-closed) if it was not staged.
    std::optional<ScalarCollateralPolicy> GetCollateralPolicy(const uint256& collateral_asset_id) const
    {
        const auto it = m_collateral.find(collateral_asset_id);
        if (it == m_collateral.end()) return std::nullopt;
        return it->second;
    }

    //! `empty`/`size` describe the scalar-fixing map ONLY (not the collateral map). Snapshot
    //! attachment to PrecomputedTransactionData is driven by leaf DETECTION in the pre-scan
    //! (`scalarcfd_settle_inputs > 0`, validation.cpp), NOT by `empty()` — so these remain a plain
    //! fixing-count accessor for tests/diagnostics and are deliberately not coupled to the
    //! collateral map a 4c settlement also reads.
    bool empty() const { return m_map.empty(); }
    size_t size() const { return m_map.size(); }

private:
    std::map<ScalarFixingKey, ResolvedScalar> m_map;
    std::map<uint256, ScalarCollateralPolicy> m_collateral;
};

//! Resolve a parsed canonical leaf's effective scalar and add it to `snapshot`, keyed by the
//! leaf's committed coordinates. v1 resolves ISSUER_PUBLISHED only (via ResolveScalarFixing over
//! `reader` + the deadline/fallback rule); CHAIN_INTRINSIC is intentionally NOT resolved here
//! (no entry added -> the opcode's lookup misses -> SCALARCFD_FIXING), pending a later
//! chain-reader slice. Returns true iff an entry was added (i.e. a usable real fixing or the
//! committed fallback fired); false on a non-issuer source or a still-pending fixing.
bool AddResolvedScalarLeaf(const ScalarCfdLeaf& leaf, int context_height, int maturity_depth,
                           int fallback_grace, const ScalarReader& reader,
                           ScalarFixingSnapshot& snapshot);

//! The §2.3-step-4 collateral gate verdict over a resolved collateral policy (pure). Returns true
//! iff the asset is usable as OP_SCALAR_CFD_SETTLE collateral: it carries COLLATERAL_SAFE and has
//! clean kyc_flags / tfr_flags / no WRAP_REQUIRED in icu_flags. Defined in the .cpp so the
//! WRAP_REQUIRED constant (assets/asset.h) stays out of the low-level script interpreter.
bool CollateralPolicyGatePasses(const ScalarCollateralPolicy& pol);

#endif // BITCOIN_CONSENSUS_SCALAR_CFD_SNAPSHOT_H
