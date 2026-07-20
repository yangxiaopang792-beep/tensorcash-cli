// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace Consensus {

static constexpr int MODEL_REGISTER_DEPOSIT_TX_VERSION{5};
static constexpr int MODEL_REGISTER_COMMIT_TX_VERSION{6};
static constexpr int MODEL_REGISTER_BURN_TX_VERSION{7};
static constexpr int MODEL_ACCUSATION_TX_VERSION{8};
static constexpr int MODEL_CHALLENGE_COMMIT_TX_VERSION{9};
static constexpr unsigned int CHALLENGE_VERIFICATION_BLOCK_COUNT{100};

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
    /** Period of blocks to check signalling in (usually retarget period, ie params.DifficultyAdjustmentInterval()) */
    uint32_t period{2016};
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t threshold{1916};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    uint256 hashGenesisBlockShort;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    std::array<BIP9Deployment,MAX_VERSION_BITS_DEPLOYMENTS> vDeployments;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    // Use TensorCash block subsidy schedule instead of classic halving.
    // When enabled, GetBlockSubsidy() applies a Tensor-specific epoch-based
    // decay (see validation.cpp) governed by fixed constants.
    bool tensor_subsidy{false};

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }

    bool external_api{false};

    std::string DefaultModelName;
    std::string DefaultModelCommit;
    std::string DefaultModelCID;

    // Activation height for per-output asset TLVs and rules.
    // At heights below this value, transactions using vExt (asset TLVs)
    // are consensus-invalid.
    int AssetsHeight{0};

    // Activation height for delegated/reusable KYC (IssuerReg v2 with a non-null
    // compliance_delegate_asset_id). Below this height, any IssuerReg carrying a
    // delegate pointer is consensus-invalid. Defaults to 0 (active from genesis),
    // mirroring AssetsHeight. Main/test chains hardwire 0; ONLY the regtest
    // constructors honor the -assetsheight / -assetsdelegationheight overrides
    // (consensus must never depend on node-local configuration). See REUSABLE_KYC.md.
    int AssetsDelegationHeight{0};

    // Activation height for the scalar-CFD subsystem (CFD_GENERALISATION.md). At or
    // above this height, ISSUER_SCALAR (0x11) publication carriers become a valid
    // output-TLV type and ConnectBlock validates/indexes them. Defaults to "never"
    // (std::numeric_limits<int>::max()) so it is INERT on all production chains until
    // a coordinated height is set; the regtest-family constructors lower it (default
    // 0, overridable via -scalarcfdheight) so tests can exercise it. Consensus must
    // never depend on node-local config, so only regtest honors the override.
    int ScalarCfdHeight{std::numeric_limits<int>::max()};
    // Burial depth before a published scalar is usable by settlement (reorg-stable),
    // and the post-deadline grace before the committed fallback fires. GRACE MUST be
    // >= MATURITY so a pre-deadline real fixing always buries before fallback can win
    // (CFD_GENERALISATION.md §3.4). Consumed by Slices 2-3; defined here for completeness.
    int SCALARCFD_MATURITY_DEPTH{100};
    int SCALARCFD_FALLBACK_GRACE{100};

    // Minimum bond (nValue) required on the initial IssuerReg (ICU) output of a new
    // asset registration. Consensus-critical: enforced in ConnectBlock, so it MUST be
    // identical network-wide (it was previously read from -assetminicubond, which made
    // block validity depend on node-local configuration).
    CAmount AssetMinIcuBond{5 * COIN};

    // Minimum bond (nValue) accepted on the initial IssuerReg of a root-sponsored child
    // asset (ticker ROOT.SUFFIX), in lieu of AssetMinIcuBond. Consensus-critical and
    // identical network-wide for the same reasons as AssetMinIcuBond. Only honored when
    // the registering transaction co-spends the sponsoring root's current ICU and that
    // prevout is itself at least AssetMinIcuBond (see ConnectBlock, ICU_CHILD.md §3).
    // Intentionally above dust so children carry a small anti-spam cost. Active from
    // genesis on all networks (pure relaxation, no versionbits — ICU_CHILD.md §4).
    CAmount SponsoredChildMinIcuBond{10'000};

    // Normalizer for model difficulty → adjusted-bits mapping.
    // nAdjBits target must be ≤ base_target * ModelDifficultyNormalizer / difficulty.
    // With difficulty == ModelDifficultyNormalizer, nAdjBits == nBits.
    uint64_t ModelDifficultyNormalizer{1000000};

    // Required collateral for model registration deposit transactions.
    CAmount ModelRegistrationDeposit{5 * COIN};

    // Minimum block delay before a successful registration deposit can be reclaimed.
    // Ensures model deposits remain frozen for a probationary period.
    int ModelCommitRefundDelay{10000};

    // Number of blocks after deposit before registration outcome is evaluated.
    uint32_t ModelVerificationBlockCount{100};

    // Minimum number of successful commit transactions required for a model to be registered.
    uint32_t ModelSuccessfulCommitsThreshold{50};

    // Deposit required to submit a challenge/accusation transaction.
    CAmount ModelChallengeDeposit{5 * COIN};

    // Number of blocks after a challenge deposit before the verdict is evaluated.
    uint32_t ModelChallengeVerdictBlockCount{CHALLENGE_VERIFICATION_BLOCK_COUNT};

    // Activation height for VDF SPV Merkle commitment (hashPoW = Merkle root of CPowBlob leaves).
    // 0 = active from genesis. Use a positive height to activate later if needed.
    // Default: active from genesis (always use Merkle commitment).
    int vdf_spv_commitment_height{0};
    
    bool IsVdfSpvActive(int height) const { return height >= vdf_spv_commitment_height; }

    // Height from which VDF proof verification becomes consensus-critical.
    // Default 0 for immediate activation on fresh networks.
    int vdf_spv_vdfverify_height{0};
    bool IsVdfVdfVerifyActive(int height) const { return height >= vdf_spv_vdfverify_height; }

    // Height from which the quick verifier's realised reuse entropy score is
    // consensus-critical. Set to a future height on live chains to avoid
    // retroactively invalidating already accepted blocks.
    int reuse_entropy_height{std::numeric_limits<int>::max()};
    bool IsReuseEntropyActive(int height) const
    {
        return height >= 0 && reuse_entropy_height >= 0 && height >= reuse_entropy_height;
    }

    // ---- V3 prompt binding / admission (TIP-0003) ----
    // First height where the v3 proof rules are enforced for proof.version >= 3:
    // nonce-bound step hashing (§7), consensus-fixed sampler profile (§2),
    // conservative B_cred tiering (§4/§5) and the Argon2id admission puzzle (§6).
    // Defaults to "never" so NOTHING changes on any chain until a chainparams
    // release sets a coordinated height. Below this height (and for
    // proof.version < 3 at any height) verification is byte-identical to v2.
    int V3ActivationHeight{std::numeric_limits<int>::max()};
    bool IsV3Active(int height) const
    {
        return height >= 0 && height >= V3ActivationHeight;
    }

    // v3 chain constants (§1). Historical verification must always read these
    // from the chain params active for the block's chain — never from mutable
    // off-chain policy. Defaults mirror the vendored implementation
    // (verification/pow_v3.h); the QuickVerifier cross-checks the profile /
    // parser-bound fields against the compiled-in pow_v3 constants and refuses
    // to verify v3 proofs on divergence (fail closed, never mis-verify).
    //
    // Tier thresholds in credited bits (§5): B_cred < B_FLOOR => invalid;
    // B_FLOOR <= B_cred < B_FREE => admission required; else free.
    uint64_t V3BFloorBits{45};
    uint64_t V3BFreeBits{70};
    // ELIG_ALPHA (§1): expected Argon2 admission cost as a fraction of decode
    // cost per 256-token window, as an exact rational (0.04 = 4/100).
    uint64_t V3EligAlphaNum{4};
    uint64_t V3EligAlphaDen{100};
    // ARGON_PROFILE (§1/§6): Argon2id time cost, memory (KiB, the security
    // parameter — do NOT trade it down for cost), lanes.
    uint32_t V3ArgonTimeCost{1};
    uint32_t V3ArgonMemoryKiB{8192};
    uint32_t V3ArgonLanes{1};
    // Reference timings in integer microseconds (§6 target derivation):
    // expected_tries = alpha * (decode_us_at_normalizer * normalizer /
    // difficulty) / argon_ref_us, exact integer arithmetic.
    uint64_t V3ArgonRefUs{4000};            // CALIBRATION: 4010us EPYC 7R13 (2026-07-07)
    uint64_t V3DecodeUsAtNormalizer{6000000}; // CALIBRATION: B=1 5.97s L40S -> tries=60
    // Consensus parser bounds for the v3 extra_flags nonce carrier (§3);
    // violations mean "no nonce claimed", never a parse failure.
    uint64_t V3ExtraFlagsMaxBytes{4096};
    int V3ExtraFlagsMaxDepth{8};
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
