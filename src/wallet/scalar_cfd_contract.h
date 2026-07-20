// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCALAR_CFD_CONTRACT_H
#define BITCOIN_WALLET_SCALAR_CFD_CONTRACT_H

// Bilateral (two-party) scalar CFD — pure derivation core (CFD_GENERALISATION.md §7, Slice 5f). The
// scalar analogue of wallet/difficulty_contract.{h,cpp}: two self-settling legs (each its own
// OP_SCALAR_CFD_SETTLE vault) sharing one issuer-published scalar fixing. The long-leg vault settles
// loss_direction 0 (owner = long party, cp = short party); the short-leg vault settles loss_direction 1
// (owner = short, cp = long). Settlement reuses the consensus opcode (Slices 1-4) via the canonical leaf
// builder BuildScalarCfdLeaf; the cooperative path is a 2-of-2 of the parties' internal keys. The
// propose/accept handshake carries Fair-Sign adaptor points for atomic risk transfer at open (free-option
// prevention), exactly mirroring the difficulty lifecycle. Everything here is PURE (no wallet/UTXO state).

#include <consensus/scalar_cfd.h>      // ComputeScalarCfdPayout, ResolvedScalar
#include <consensus/scalar_cfd_leaf.h> // ScalarCfdSourceType / PayoffMode
#include <key.h>                       // CKey (FS adaptor derivation)
#include <primitives/transaction.h>    // COutPoint, CTxIn, CTxOut
#include <pubkey.h>
#include <script/script.h>
#include <script/signingprovider.h>    // TaprootBuilder
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wallet {

//! One leg's margin + payout keys. owner_key receives (IM − loss); cp_key receives the loss transfer.
struct ScalarCfdLegTerms {
    uint64_t im{0};            //!< posted Initial Margin, in the collateral's units (sats if native)
    uint32_t lambda_q{0};      //!< leverage in Q16 (lambda = lambda_q / 2^16)
    XOnlyPubKey owner_key{};   //!< this leg's owner payout key
    XOnlyPubKey cp_key{};      //!< counterparty payout key

    SERIALIZE_METHODS(ScalarCfdLegTerms, obj) { READWRITE(obj.im, obj.lambda_q, obj.owner_key, obj.cp_key); }
};

//! Whole-contract terms: two self-settling legs + the shared scalar fixing (the §2.2 leaf economics that
//! are NOT per-leg). contract_id randomised by a salt so economically-identical trades are distinct.
struct ScalarCfdContractTerms {
    ScalarCfdLegTerms long_leg;     //!< loses as X falls below K (loss_direction 0x00); owner = long party
    ScalarCfdLegTerms short_leg;    //!< loses as X rises above K (loss_direction 0x01); owner = short party

    uint8_t  source_type{static_cast<uint8_t>(ScalarCfdSourceType::ISSUER_PUBLISHED)};
    uint8_t  payoff_mode{static_cast<uint8_t>(ScalarCfdPayoffMode::STRIKE)};
    uint256  underlying_asset_id{}; //!< U (zero iff CHAIN_INTRINSIC)
    uint32_t feed_id{0};
    uint64_t fixing_ref{0};
    uint32_t publication_deadline_height{0};
    uint32_t settle_lock_height{0}; //!< leaf CLTV (belt-and-suspenders, §2.1)
    uint16_t scalar_format_id{0};
    uint256  strike{};              //!< K
    uint256  fallback_scalar{};
    uint256  collateral_asset_id{}; //!< C; 32 zero bytes = NATIVE_SENTINEL

    SERIALIZE_METHODS(ScalarCfdContractTerms, obj) {
        READWRITE(obj.long_leg, obj.short_leg, obj.source_type, obj.payoff_mode, obj.underlying_asset_id,
                  obj.feed_id, obj.fixing_ref, obj.publication_deadline_height, obj.settle_lock_height,
                  obj.scalar_format_id, obj.strike, obj.fallback_scalar, obj.collateral_asset_id);
    }

    //! v1 validity: in-range source/payoff, source-consistent U, known scalar_format, both legs with
    //! non-zero lambda + IM >= MIN_SETTLE_OUTPUT + valid distinct payout keys, settle_lock in
    //! [1, LOCKTIME_THRESHOLD), and (native collateral) MoneyRange IMs. Sets `err`.
    bool Validate(std::string& err) const;
};

//! Persisted record (mirrors DifficultyContractRecord): open-time state settlement needs after a restart.
struct ScalarCfdContractRecord {
    uint256 contract_id{};
    uint256 salt{};
    ScalarCfdContractTerms terms;

    XOnlyPubKey long_internal_key{};   //!< NUMS_H in v1 (key path disabled)
    XOnlyPubKey short_internal_key{};
    COutPoint long_vault{};
    COutPoint short_vault{};
    uint256 open_txid{};

    XOnlyPubKey long_owner_internal{};  //!< internal keys behind the payout addresses (coop 2-of-2 signers)
    XOnlyPubKey long_cp_internal{};
    XOnlyPubKey short_owner_internal{};
    XOnlyPubKey short_cp_internal{};

    XOnlyPubKey fs_tx_adaptor_point{};                     //!< proposer's FS adaptor point (offer)
    std::optional<XOnlyPubKey> counterparty_adaptor_point; //!< acceptor's FS adaptor point (acceptance)
    uint256 fs_context{};                                  //!< the offer commitment (FS KDF context)

    const XOnlyPubKey& VaultInternalKey(bool is_short) const { return is_short ? short_internal_key : long_internal_key; }
    const COutPoint& VaultOutpoint(bool is_short) const { return is_short ? short_vault : long_vault; }
    const XOnlyPubKey& CoopOwnerInternal(bool is_short) const { return is_short ? short_owner_internal : long_owner_internal; }
    const XOnlyPubKey& CoopCpInternal(bool is_short) const { return is_short ? short_cp_internal : long_cp_internal; }
    // The PAYOUT (output) keys anchoring each coop signer's wallet provider — owner = the leg party, cp = the
    // counterparty. The coop leaf is a 2-of-2 of the INTERNAL keys behind these addresses.
    const XOnlyPubKey& CoopOwnerKey(bool is_short) const { return is_short ? terms.short_leg.owner_key : terms.long_leg.owner_key; }
    const XOnlyPubKey& CoopCpKey(bool is_short) const { return is_short ? terms.short_leg.cp_key : terms.long_leg.cp_key; }

    // Explicit serialize so the adaptor fields append backward-compatibly (a pre-adaptor record has no
    // trailing bytes; Unserialize leaves them defaulted) — same scheme as DifficultyContractRecord.
    template <typename Stream> void Serialize(Stream& s) const {
        s << contract_id << salt << terms
          << long_internal_key << short_internal_key << long_vault << short_vault << open_txid
          << long_owner_internal << long_cp_internal << short_owner_internal << short_cp_internal;
        const bool has_fs = !fs_tx_adaptor_point.IsNull();
        s << has_fs;
        if (has_fs) {
            s << fs_tx_adaptor_point;
            const bool has_cp = counterparty_adaptor_point.has_value();
            s << has_cp;
            if (has_cp) s << *counterparty_adaptor_point;
            s << fs_context;
        }
    }
    template <typename Stream> void Unserialize(Stream& s) {
        s >> contract_id >> salt >> terms
          >> long_internal_key >> short_internal_key >> long_vault >> short_vault >> open_txid
          >> long_owner_internal >> long_cp_internal >> short_owner_internal >> short_cp_internal;
        fs_tx_adaptor_point = XOnlyPubKey{};
        counterparty_adaptor_point.reset();
        fs_context = uint256{};
        if (s.size() == 0) return;
        bool has_fs = false; s >> has_fs;
        if (!has_fs) return;
        s >> fs_tx_adaptor_point;
        bool has_cp = false; s >> has_cp;
        if (has_cp) { XOnlyPubKey p; s >> p; counterparty_adaptor_point = p; }
        s >> fs_context;
    }
};

//! contract_id = H(terms || salt).
uint256 ComputeScalarCfdContractId(const ScalarCfdContractTerms& terms, const uint256& salt);

//! Full record integrity gate (persistence + pre-build), STATE-AWARE. Always enforces, beyond
//! Validate()-on-terms: contract_id == ComputeScalarCfdContractId(terms, salt) (and == *expected_key when
//! given); the v1 accepted-state invariants the open/settlement paths rely on — BOTH vault internal keys ==
//! BIP341 NUMS_H (key path provably disabled), all four coop 2-of-2 internal keys valid, BOTH Fair-Sign
//! adaptor points present + valid, and a non-null fs_context.
//!
//! If the record is in the OPENED state (open_txid or either vault outpoint set), it ADDITIONALLY enforces
//! the opened invariant: open_txid non-null AND both vault outpoints non-null (n != NULL_INDEX) AND both
//! reference open_txid. The output-vs-rebuilt-script/IM matching is chain-dependent and is enforced by
//! record_open at the tx level, not here. Sets `err` on failure. `expected_key` may be null.
bool ValidateScalarCfdContractRecord(const ScalarCfdContractRecord& record, const uint256* expected_key, std::string& err);

//! fs/contract_meta: binds contract_id + both adaptor points (the open PSBT carries it so adaptor.prepare
//! can locate the contract). The acceptor point may be absent on a half-built record.
uint256 ComputeScalarCfdContractMeta(const ScalarCfdContractRecord& record);

//! FS roles folded into the adaptor KDF so proposer/acceptor secrets never collide.
enum : uint8_t { SCALAR_CFD_FS_ROLE_PROPOSER = 0, SCALAR_CFD_FS_ROLE_ACCEPTOR = 1 };

//! The adaptor KDF context: a commitment over the proposer's stable offer fields (feed terms + leg
//! IMs/lambdas + the proposer's own payout keys + side + salt — NOT the acceptor's keys, NOT contract_id,
//! since the proposer derives at propose time where neither exists). Computed identically by both parties.
uint256 ComputeScalarCfdOfferCommitment(uint8_t proposer_is_short, const ScalarCfdContractTerms& terms,
                                        const XOnlyPubKey& proposer_owner_key,
                                        const XOnlyPubKey& proposer_cp_key, const uint256& salt);

//! Deterministically derive THIS party's Fair-Sign adaptor (secret, x-only point) from the private key
//! behind its owner payout + salt + context (== fs_context) + role. Stateless/re-derivable; the secret is
//! never persisted or transmitted. Throws if no valid scalar is found.
std::pair<uint256, XOnlyPubKey> DeriveScalarCfdFsAdaptor(const CKey& owner_key, const uint256& salt,
                                                         const uint256& context, uint8_t role);

//! Build the canonical §2.2 settlement leaf for one leg (signatureless / keeper-spendable): reuses
//! BuildScalarCfdLeaf with the leg's owner/cp/lambda/im and the shared fixing terms; loss_direction = is_short.
CScript BuildScalarCfdLegLeaf(const ScalarCfdContractRecord& record, bool is_short);

//! Cooperative-close leaf for one leg: 2-of-2 of the leg's internal (descriptor) keys
//!   <owner_internal32> OP_CHECKSIGVERIFY <cp_internal32> OP_CHECKSIG
CScript BuildScalarCfdCoopLeaf(const ScalarCfdContractRecord& record, bool is_short);

//! Per-leg Taproot vault: {settle_leaf, coop_leaf} under `internal_key` (NUMS_H in v1).
TaprootBuilder CreateScalarCfdVaultBuilder(const ScalarCfdContractRecord& record, bool is_short,
                                           const XOnlyPubKey& internal_key);

//! The covenant-conserved part of a unilateral settlement of ONE leg vault: the vault input with the
//! keeper witness [settle_leaf, control], the exact payout output(s), and nLockTime == settle_lock_height.
struct ScalarCfdSettlementSkeleton {
    CTxIn vault_input;
    std::vector<CTxOut> payouts;
    uint32_t nlocktime{0};
    ScalarCfdPayout payout;
};

//! Build the settlement skeleton for one leg from the RECORD (vault outpoint + reconstructed control
//! block). Computes the payout via the SAME path the opcode uses (ComputeScalarCfdPayout) from the
//! caller-resolved scalar `realized` (decoded). Payout legs are AssetTag(C, leg) for asset collateral or
//! native for NATIVE_SENTINEL. The settlement dust is NOT a parameter — it is the consensus constant the
//! opcode enforces (MIN_SETTLE_OUTPUT as the payout-snap floor, SCALARCFD_ASSET_OUTPUT_DUST as the asset
//! carrier nValue, interpreter.cpp); any other value would build a tx the covenant rejects. `out` written
//! only on success. SECURITY: `realized` MUST be the chain-resolved fixing (ResolveScalarFixing) — a wrong
//! value just yields outputs the covenant rejects.
bool BuildScalarCfdSettlementSkeleton(const ScalarCfdContractRecord& record, bool is_short,
                                      const arith_uint256& realized,
                                      ScalarCfdSettlementSkeleton& out, std::string& err);

} // namespace wallet

#endif // BITCOIN_WALLET_SCALAR_CFD_CONTRACT_H
