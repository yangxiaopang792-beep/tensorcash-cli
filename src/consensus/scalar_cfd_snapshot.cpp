// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/scalar_cfd_snapshot.h>

#include <assets/asset.h> // assets::COLLATERAL_SAFE / WRAP_REQUIRED for the §5.1 gate

bool CollateralPolicyGatePasses(const ScalarCollateralPolicy& pol)
{
    return pol.collateral_safe
        && pol.kyc_flags == 0
        && pol.tfr_flags == 0
        && (pol.icu_flags & assets::WRAP_REQUIRED) == 0;
}

bool AddResolvedScalarLeaf(const ScalarCfdLeaf& leaf, int context_height, int maturity_depth,
                           int fallback_grace, const ScalarReader& reader,
                           ScalarFixingSnapshot& snapshot)
{
    // v1: only the issuer-published feed is resolvable here. CHAIN_INTRINSIC settlement reads an
    // objective chain metric via a difficulty-style reader wired in a later slice; until then it
    // adds no entry, so the opcode's lookup misses and it fails closed (SCALARCFD_FIXING).
    if (leaf.source_type != static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED)) {
        return false;
    }

    // Burial + the deadline/fallback rule (§3.4) are applied here, single-threaded. The result is
    // the REAL fixing (if usable & buried), else the committed fallback (past deadline+grace), else
    // nullopt = still pending (no entry -> the opcode waits / fails this attempt).
    const std::optional<ResolvedScalar> resolved = ResolveScalarFixing(
        leaf.underlying_asset_id, leaf.feed_id, leaf.fixing_ref,
        leaf.publication_deadline_height, leaf.fallback_scalar, leaf.scalar_format_id,
        context_height, maturity_depth, fallback_grace, reader);
    if (!resolved) return false;

    const ScalarFixingKey key{leaf.source_type, leaf.underlying_asset_id, leaf.feed_id, leaf.fixing_ref};
    snapshot.Add(key, *resolved);
    return true;
}
