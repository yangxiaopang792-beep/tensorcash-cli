// Copyright (c) 2026 The Tensorcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_DIFFICULTY_CONTRACT_H
#define BITCOIN_WALLET_DIFFICULTY_CONTRACT_H

#include <consensus/amount.h>
#include <consensus/difficulty_cfd.h> // DiffCfdPayout
#include <key.h>                       // CKey (DeriveDifficultyFsAdaptor)
#include <primitives/transaction.h>   // CTxIn / CTxOut / COutPoint
#include <pubkey.h>
#include <script/script.h>
#include <script/signingprovider.h> // TaprootBuilder
#include <serialize.h>
#include <uint256.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wallet {

//! Per-leg (per-vault) terms of a difficulty derivative. One leg == one IM vault that settles only
//! its own posted margin as a function of nBits @ the fixing height (DIFFICULTY_DERIVATIVE.md §1.1).
//! The two payout keys are the committed Taproot output keys the settlement covenant pays to.
struct DifficultyLegTerms {
    CAmount im{0};            //!< posted Initial Margin (native sats in v1)
    uint256 im_asset{};       //!< collateral asset; null/zero == native. Non-native is v2 (rejected in v1).
    uint32_t lambda_q{0};     //!< leverage in Q16 (lambda = lambda_q / 2^16)
    XOnlyPubKey owner_key{};  //!< this leg's owner payout key (receives IM - loss)
    XOnlyPubKey cp_key{};     //!< counterparty payout key (receives the loss)

    SERIALIZE_METHODS(DifficultyLegTerms, obj) {
        READWRITE(obj.im, obj.im_asset, obj.lambda_q, obj.owner_key, obj.cp_key);
    }
};

//! Contract kind. A CFD is the symmetric two-margined-leg instrument; an OPTION funds only ONE leg (the
//! writer's IM vault) and the buyer pays an upfront premium (buyer→writer) at open instead of posting
//! margin. Both settle through the exact same OP_DIFFCFD_SETTLE leaf — an option is just a single
//! difficulty vault (owner = writer, cp = buyer) plus a premium output.
enum : uint8_t { DIFFICULTY_KIND_CFD = 0, DIFFICULTY_KIND_OPTION = 1 };

//! Whole-contract terms: two self-settling legs plus the shared underlying (strike + fixing height).
struct DifficultyContractTerms {
    DifficultyLegTerms long_leg;     //!< loses as difficulty FALLS (loss_direction 0x00)
    DifficultyLegTerms short_leg;    //!< loses as difficulty RISES (loss_direction 0x01)
    uint32_t strike_nbits{0};        //!< committed compact difficulty target (must be canonical)
    uint32_t fixing_height{0};       //!< buried ancestor height H whose nBits is the underlying
    uint32_t settle_lock_height{0};  //!< leaf CLTV; must be >= fixing_height + DIFFCFD_MATURITY_DEPTH
    uint8_t kind{DIFFICULTY_KIND_CFD};  //!< DIFFICULTY_KIND_CFD (both legs) or DIFFICULTY_KIND_OPTION (one leg + premium)
    CAmount premium{0};              //!< OPTION only: buyer→writer upfront payment (native sats); MUST be 0 for a CFD

    SERIALIZE_METHODS(DifficultyContractTerms, obj) {
        READWRITE(obj.long_leg, obj.short_leg, obj.strike_nbits, obj.fixing_height, obj.settle_lock_height,
                  obj.kind, obj.premium);
    }

    bool IsOption() const { return kind == DIFFICULTY_KIND_OPTION; }
    //! For a (validated) OPTION, the writer's single funded leg is the one carrying margin.
    bool OptionWriterIsShort() const { return short_leg.im > 0; }
    const DifficultyLegTerms& OptionWriterLeg() const { return OptionWriterIsShort() ? short_leg : long_leg; }

    //! v1 validity: native-only IM, non-zero leverage, margin >= MIN_SETTLE_OUTPUT, valid payout keys,
    //! canonical strike, fixing height within consensus int range, and a CLTV aligned (overflow-safe)
    //! with the consensus burial bound. Sets `err` on failure.
    //!
    //! When `pow_limit` is non-null, the strike is additionally checked to DECODE within that chain's
    //! powLimit exactly as the consensus OP_DIFFCFD_SETTLE does (FixingContext::DecodeTarget /
    //! DeriveTarget) — a canonical-but-above-powLimit strike would otherwise pass here yet be
    //! unspendable on-chain. Callers with chain access (the RPC) MUST pass the chain powLimit.
    bool Validate(std::string& err, const uint256* pow_limit = nullptr) const;
};

//! Persisted record (analogue of ForwardContractRecord). Carries the open-time state that
//! build_settlement needs after a restart — the funded vault outpoints and the internal keys that
//! reconstruct each vault's Taproot control block — so settlement never depends on fragile UTXO
//! rediscovery.
struct DifficultyContractRecord {
    uint256 contract_id{};            //!< = ComputeDifficultyContractId(terms, salt)
    uint256 salt{};                   //!< randomizes contract_id so economically-identical trades are distinct records
    DifficultyContractTerms terms;

    // Vault binding — populated by build_open once the open tx funds the two vaults; null until opened.
    //! Vault internal keys. In v1 BOTH are the fixed BIP341 NUMS point (XOnlyPubKey::NUMS_H), so the
    //! key path is provably disabled; the two vaults still get DISTINCT output keys because their
    //! committed leaves differ (the taptweak folds in the per-vault merkle root). v2 replaces these
    //! with the spendable MuSig2 aggregate key for the cooperative path.
    XOnlyPubKey long_internal_key{};
    XOnlyPubKey short_internal_key{};
    COutPoint long_vault{};           //!< funded long-leg vault UTXO
    COutPoint short_vault{};          //!< funded short-leg vault UTXO
    uint256 open_txid{};              //!< the open transaction id

    //! Cooperative-close cosign keys: the INTERNAL (descriptor) x-only key behind each party's payout
    //! address, populated from the offer/acceptance handshake (each party extracts its own). The coop leaf
    //! is a 2-of-2 of these (the wallet signs them directly via its descriptor — unlike the tweaked output
    //! keys). NOT part of contract_id; bound instead by being committed in the coop leaf (vault address).
    XOnlyPubKey long_owner_internal{};   //!< internal key behind long_leg.owner_key
    XOnlyPubKey long_cp_internal{};      //!< internal key behind long_leg.cp_key
    XOnlyPubKey short_owner_internal{};  //!< internal key behind short_leg.owner_key
    XOnlyPubKey short_cp_internal{};     //!< internal key behind short_leg.cp_key

    const XOnlyPubKey& VaultInternalKey(bool is_short) const { return is_short ? short_internal_key : long_internal_key; }
    const COutPoint& VaultOutpoint(bool is_short) const { return is_short ? short_vault : long_vault; }
    //! Cooperative-close cosign keys: the INTERNAL (untweaked descriptor) key behind each party's payout
    //! address. The coop leaf is a 2-of-2 of these; each party signs with the internal private key its
    //! wallet holds for its own payout address — obtained from that address's EXPANDED signing provider
    //! (a wallet-global GetKeyByXOnly cannot reverse a raw keyid to a descriptor index, but the address's
    //! own provider, expanded at the right index, exposes the key in `keys`). The payout OUTPUT keys are
    //! the addresses that anchor those providers (and are already committed in contract_id).
    const XOnlyPubKey& CoopOwnerInternal(bool is_short) const { return is_short ? short_owner_internal : long_owner_internal; }
    const XOnlyPubKey& CoopCpInternal(bool is_short) const { return is_short ? short_cp_internal : long_cp_internal; }
    const XOnlyPubKey& CoopOwnerKey(bool is_short) const { return is_short ? terms.short_leg.owner_key : terms.long_leg.owner_key; }
    const XOnlyPubKey& CoopCpKey(bool is_short) const { return is_short ? terms.short_leg.cp_key : terms.long_leg.cp_key; }

    //! Fair-Sign adaptor points for ATOMIC RISK TRANSFER at open (free-option prevention). The
    //! proposer's point is carried in the offer, the acceptor's in the acceptance; each party derives
    //! its OWN secret deterministically from the private key behind its owner payout (see
    //! DeriveDifficultyFsAdaptor) — so neither secret is persisted or sent on the wire. Null on records
    //! created before atomic-open existed (those simply can't use the ceremony). Bound into the
    //! fs/contract_meta the open PSBT carries via ComputeDifficultyContractMeta — NOT part of contract_id.
    XOnlyPubKey fs_tx_adaptor_point{};                      //!< proposer's adaptor point (offer)
    std::optional<XOnlyPubKey> counterparty_adaptor_point;  //!< acceptor's adaptor point (acceptance)
    //! The adaptor KDF `context` (= ComputeDifficultyOfferCommitment over the proposer's committed offer
    //! fields). Stored so BOTH parties re-derive their secret at ceremony time identically to how they
    //! derived it at propose/accept — using the SAME context everywhere. It must be the offer commitment,
    //! NOT contract_id: the proposer derives its point at propose, where contract_id does not yet exist.
    uint256 fs_context{};

    // Explicit (not SERIALIZE_METHODS) so the adaptor fields can be APPENDED backward-compatibly: a
    // record written before they existed has no trailing bytes, and Unserialize leaves them defaulted.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << contract_id << salt << terms
          << long_internal_key << short_internal_key
          << long_vault << short_vault << open_txid
          << long_owner_internal << long_cp_internal
          << short_owner_internal << short_cp_internal;
        s << fs_tx_adaptor_point;
        const bool has_cp_point = counterparty_adaptor_point.has_value();
        s << has_cp_point;
        if (has_cp_point) s << *counterparty_adaptor_point;
        s << fs_context;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> contract_id >> salt >> terms
          >> long_internal_key >> short_internal_key
          >> long_vault >> short_vault >> open_txid
          >> long_owner_internal >> long_cp_internal
          >> short_owner_internal >> short_cp_internal;
        fs_tx_adaptor_point = XOnlyPubKey{};
        counterparty_adaptor_point.reset();
        fs_context = uint256{};
        // Backward-compat: adaptor fields are absent in pre-atomic-open records (no trailing bytes).
        if (s.size() > 0) {
            s >> fs_tx_adaptor_point;
            bool has_cp_point = false;
            s >> has_cp_point;
            if (has_cp_point) {
                XOnlyPubKey p;
                s >> p;
                counterparty_adaptor_point = p;
            }
            // fs_context was appended after the points; tolerate a record written before it existed.
            if (s.size() > 0) {
                s >> fs_context;
            }
        }
    }
};

//! contract_id = H(serialized terms || salt). The salt makes two economically-identical contracts
//! distinct records (otherwise they would collide in storage, which uses insert_or_assign keyed by
//! contract_id). Note: vault output-key uniqueness comes from the committed leaf via the taptweak,
//! NOT from the internal key — so v1 can safely use the same NUMS_H internal key for every vault.
uint256 ComputeDifficultyContractId(const DifficultyContractTerms& terms, const uint256& salt);

//! Human-readable representation of a compact difficulty target (nBits) as the implied network inference
//! throughput in TOKENS/SEC, for display in difficulty term sheets and pricing (raw nBits is opaque).
//! Grounded in the chain's own work metric: the expected number of genesis solution windows to find a
//! block is 2^256/(target+1) (identical to GetBlockProof / chainwork-per-block), each window is W=256
//! generated tokens (Verification Whitepaper, mainnet inception), and blocks target nPowTargetSpacing =
//! 600 s. So tokens/sec = (2^256/(target+1)) * 256 / 600. The genesis model is the 1x difficulty
//! baseline (MODEL_VERIFICATION.md), so no per-model FLOPs adjustment applies. Returns 0 for an
//! undecodable / zero / negative / overflowing target.
double DifficultyNBitsToTokensPerSec(uint32_t nbits);

//! Inverse of DifficultyNBitsToTokensPerSec: given a human-chosen strike in TOKENS/SEC, return the
//! canonical compact target (nBits) the contract settles on. The compact encoding is lossy, so the
//! round-trip is not bit-exact — callers should display the REALIZED throughput
//! (DifficultyNBitsToTokensPerSec of the result). Returns 0 for a non-positive input.
uint32_t DifficultyTokensPerSecToNBits(double tokens_per_sec);

//! Compact SI rendering of an inference throughput (tokens/sec), e.g. "5.00G tok/s", for difficulty
//! strike/term-sheet display. Returns "n/a" for a non-positive value. Shared by the wizard, the
//! review dialog and the trade board so the representation never drifts.
std::string DifficultyFormatTokensPerSec(double tokens_per_sec);

//! fs/contract_meta for the Fair-Sign adaptor ceremony: a deterministic id BOTH parties compute
//! identically once they hold the contract record (binds contract_id + both adaptor points). Embedded
//! in the open PSBT so adaptor.prepare can locate the contract; distinct from contract_id (which does
//! not commit to the adaptor points). The acceptor point may be absent on a half-built record.
uint256 ComputeDifficultyContractMeta(const DifficultyContractRecord& record);

//! Local role byte folded into the adaptor KDF so the proposer's and acceptor's secrets never collide
//! even with the same owner key / salt / context.
enum : uint8_t { DIFFICULTY_FS_ROLE_PROPOSER = 0, DIFFICULTY_FS_ROLE_ACCEPTOR = 1 };

//! The adaptor KDF `context`: a commitment over the proposer's stable offer fields. The SAME value is
//! used by every derivation of a given contract's adaptors (proposer at propose, acceptor at accept,
//! both at ceremony) — it is computed once when the offer is known and stored in the record as
//! `fs_context`. It deliberately covers ONLY fields fixed at propose time (econ scalars + the
//! proposer's own payout keys + side + salt), NOT the acceptor's keys and NOT contract_id, because the
//! proposer must derive its point at propose where neither exists yet. Hashing the leg payout keys from
//! `terms` is avoided (those carry the acceptor's keys, unset at propose); the proposer's keys are
//! passed explicitly. `proposer_is_short` is the side the PROPOSER posted.
uint256 ComputeDifficultyOfferCommitment(uint8_t proposer_is_short, const DifficultyContractTerms& terms,
                                         const XOnlyPubKey& proposer_owner_key,
                                         const XOnlyPubKey& proposer_cp_key, const uint256& salt);

//! OPTION analogue of ComputeDifficultyOfferCommitment: the proposer commits a SINGLE payout key, and the
//! stable fields are the option econ scalars + writer side + who proposed (writer/buyer) + salt. Computed
//! identically at propose_option / accept_option / import_acceptance and stored in the record's fs_context.
uint256 ComputeDifficultyOptionOfferCommitment(uint8_t writer_is_short, uint8_t proposer_is_writer,
                                               uint32_t strike_nbits, uint32_t fixing_height,
                                               uint32_t settle_lock_height, CAmount im, uint32_t lambda_q,
                                               CAmount premium, const XOnlyPubKey& proposer_key,
                                               const uint256& salt);

//! Deterministically derive THIS party's Fair-Sign adaptor (secret scalar, x-only point) from the
//! private key behind its owner payout address + the contract salt + the contract-binding `context`
//! (== fs_context, the offer commitment above) + a `role` byte. Stateless and re-derivable wherever its
//! inputs are available, so the maker's secret never needs persisting or transmitting (free-option
//! prevention requires each party know only its own secret). The returned point is XOnlyPubKey(secret·G);
//! adaptor.prepare normalizes parity.
//!
//! KDF = H_tag(owner_priv || salt || context || role || counter). `context` is the SAME offer
//! commitment everywhere (NEVER contract_id) so the proposer's propose-time derivation reproduces
//! exactly at ceremony. `role` is DIFFICULTY_FS_ROLE_PROPOSER for the offer creator, _ACCEPTOR
//! otherwise. Throws if no valid scalar is found.
std::pair<uint256, XOnlyPubKey> DeriveDifficultyFsAdaptor(const CKey& owner_key, const uint256& salt,
                                                          const uint256& context, uint8_t role);

//! Loss-direction byte committed in a leg's settlement leaf: 0x00 long/down, 0x01 short/up.
inline uint8_t DifficultyLossDirection(bool is_short) { return is_short ? 0x01 : 0x00; }

//! Build the §2.2 unilateral settlement leaf for one leg (signatureless / keeper-spendable):
//!   <contract_id32> OP_DROP                          # per-instance uniqueness commitment (inert)
//!   <settle_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!   <fixing_height_le4> <strike_nbits_le4> <lambda_q_le4> <dir_byte> <vault_im_le8>
//!   <owner_key32> <cp_key32> OP_DIFFCFD_SETTLE
//! The leading `<contract_id> OP_DROP` is inert at execution but makes the leaf — and therefore the
//! taproot merkle root and the (NUMS_H-tweaked) vault OUTPUT KEY — unique per contract instance. This
//! is REQUIRED: with the same NUMS_H internal key, two economically-identical contracts (same terms,
//! different salt) would otherwise share a vault output key and collide in the vault registry.
//! Operating from the record (not raw terms) ensures the commitment is never omitted.
//! Byte-compatible with the OP_DIFFCFD_SETTLE consensus opcode (the prefix is just push+drop).
//! PRECONDITION: `record.terms` must have passed Validate().
CScript BuildDifficultyLeafScript(const DifficultyContractRecord& record, bool is_short);

//! Build the cooperative-close leaf for one leg: a plain 2-of-2 cosign of the leg's two payout keys
//!   <owner_key32> OP_CHECKSIGVERIFY <cp_key32> OP_CHECKSIG
//! (owner = the leg owner, cp = the counterparty — i.e. both parties). Spending it requires BOTH
//! signatures, so a cooperative close can only happen by mutual agreement; the unilateral settlement
//! leaf remains the trustless fallback. Deliberately PURE (no contract_id prefix) so standard taproot
//! script-path signing handles it — uniqueness across contracts comes from the sibling settlement leaf
//! (which commits contract_id) via the shared taptweak. Witness stack: [sig_cp, sig_owner, leaf, control].
CScript BuildDifficultyCoopLeafScript(const DifficultyContractRecord& record, bool is_short);

//! Build the per-leg Taproot vault: the keyless unilateral leaf above committed under `internal_key`.
//! v1 uses the BIP341 NUMS point (XOnlyPubKey::NUMS_H, script-path-only); the cooperative MuSig2
//! key-path (Slice 2 step 3) later supplies a real aggregate key here. PRECONDITION: validated record
//! + fully-valid `internal_key` (asserted in debug; an invalid key leaves the builder !IsComplete()).
TaprootBuilder CreateDifficultyVaultBuilder(const DifficultyContractRecord& record, bool is_short,
                                            const XOnlyPubKey& internal_key);

//! The covenant-conserved part of a unilateral settlement of ONE difficulty vault: a single vault
//! input carrying the keeper witness (no signature), the exact covenant payout output(s), and the
//! required nLockTime. The broadcaster (keeper) adds an EXTERNAL native fee input + change around
//! this — the covenant outputs are never shaved (v1 is output-conserved). Exactly one difficulty
//! vault is spent per tx (consensus §2.3 forbids co-spending both).
struct DifficultySettlementSkeleton {
    CTxIn vault_input;            //!< prevout = vault outpoint; witness = [leaf, control]; non-final sequence
    std::vector<CTxOut> payouts;  //!< 1 or 2 covenant outputs (a zero leg is skipped, exactly like consensus)
    uint32_t nlocktime{0};        //!< == settle_lock_height (satisfies the leaf CLTV)
    DiffCfdPayout payout;         //!< the computed {owner, cp} split
};

//! Build the settlement skeleton for one leg, OPERATING FROM THE RECORD: the vault outpoint comes
//! from `record.VaultOutpoint(is_short)` and the control block is reconstructed from the stored
//! internal key + leaf (so the caller cannot pass a mismatched witness). Resolves the payout via the
//! SAME path the consensus opcode uses (DeriveTarget(strike|realized, pow_limit) + ComputeDiffCfdPayout),
//! skips zero legs as the covenant does, and emits the keeper witness [leaf, control] with a non-final
//! sequence and nLockTime == settle_lock_height. Validates terms against `pow_limit` first. `out` is
//! written only on success; returns false (with `err`) on invalid terms, an out-of-range strike/realized,
//! or an unopened/invalid vault (null internal key / outpoint).
//!
//! SECURITY CONTRACT: `realized_nbits` MUST be the value the caller READ FROM THE ACTIVE CHAIN at
//! `record.terms.fixing_height` (`chain[fixing_height]->nBits`), after enforcing `tip >= fixing_height +
//! DIFFCFD_MATURITY_DEPTH`. It is NOT a trusted/user-supplied input — its only purpose here is to compute
//! the exact payout outputs the consensus opcode will independently re-derive from the chain at
//! validation. A wrong value just yields outputs the covenant rejects (the tx fails), so this is a UX
//! footgun rather than a fund-safety hole, but the RPC must still resolve it from the chain.
bool BuildDifficultySettlementSkeleton(const DifficultyContractRecord& record, bool is_short,
                                       uint32_t realized_nbits, const uint256& pow_limit,
                                       DifficultySettlementSkeleton& out, std::string& err);

} // namespace wallet

#endif // BITCOIN_WALLET_DIFFICULTY_CONTRACT_H
