# Option Tokenization — Bearer-Asset Securitization of Difficulty Options

A `DIFFICULTY_KIND_OPTION` position (DIFFICULTY_DERIVATIVE.md §6.5) is turned into N fungible,
freely-tradeable registry-asset units, where each unit is the bearer claim on 1/N of the option
payout. This introduces **no new consensus code**: it composes existing primitives — the
`OP_DIFFCFD_SETTLE` covenant, the asset registry + ICU model, `OP_OUTPUTMATCH_ASSET`, and the
root-sponsored ICU children of `ICU_CHILD.md`.

The feature is a **wallet/RPC layer**: series fan-out, pot/sink covenant builders, the issuance
ceremony, redemption, and writer buy-back — all composed over the generic sponsored-child
mechanism (`sponsorchildasset`) rather than over any option-specific consensus class. The
derivation and covenant builders live in `src/wallet/option_series.{h,cpp}`, the RPC surface in
`src/wallet/rpc/option_series.cpp`, and persistence in `src/wallet/walletdb.cpp`.

The supporting primitives this layer relies on:

- The difficulty-CFD consensus opcodes `OP_NBITS_AT` / `OP_DIFFCFD_SETTLE`, the `FixingContext`,
  the one-difficulty-input rule, and the script-cache bypass for chain-reading leaves
  (DIFFICULTY_DERIVATIVE.md).
- The wallet difficulty layer including the **bilateral OPTION kind**: `DIFFICULTY_KIND_OPTION`
  terms + validation (`src/wallet/difficulty_contract.{h,cpp}`), the option propose/accept and
  open/record RPCs (`src/wallet/rpc/difficulty.cpp`), keeper settlement.
- Asset registry invariants: hard issuance cap (`asset-cap-exceeded`), immutable-at-quorum-zero
  governance (`icu-immutable-rotation`), mandatory ICU rotation with rotate-to-burn after unlock
  (`asset-bond-rotation`), and the ICU output-binding sighash rule (`consensus/tx_verify.cpp`).
- Generic root-sponsored ICU children (`ICU_CHILD.md`): the dotted `ROOT.SUFFIX` ticker grammar,
  the `SponsoredChildMinIcuBond` (10,000-sat) floor gated on a stateless parent-ICU co-spend
  proof, the `sponsorchildasset` wallet RPC, and the `registerasset` root-only alignment. Option
  series register as ordinary low-bond children under this mechanism and prove inertness at the
  **product layer** (§2.5, §3) rather than via a consensus `Sealed()` predicate.

---

## 1. Instrument

### 1.1 Parties and shape

- **Writer / issuer** (single signer — the primary model): locks `K` TSC collateral, mints
  all `N` token units to itself, and sells them on the open market. Covered: max loss `K`,
  realizes its premium through unit sales rather than a day-1 payment, keeps `K − payout` at
  settlement. It owns the ICU, so issuance is **one self-signed tx** with no counterparty
  handshake (§2.6). The issuer is the option's counterparty *and* its creator — "make the
  asset" and "open the position by posting the IM" are the same ceremony.
- **Holders / buyers**: anyone who acquires units on the secondary market. One raw unit =
  the bearer claim on one lot's payout pot. No relationship to the issuer or each other; they
  verify the series from chain data before buying (§3, §6.5).
- **Named originator** (advanced — the §2.6 bilateral variant): a single day-1 buyer who
  *co-signs* issuance to lock premium-for-units atomically at a fixed price instead of buying
  on market. Pays premium `P`, receives all `N` units.
- **Keeper**: anyone. Settlement and redemption are permissionless.

The underlying is exactly the existing one-leg difficulty option: a `short_leg=true` vault
(writer = margin owner, loses as difficulty rises) whose `cp_key` payout — zero at/below
strike, rising λ-linearly above, clamped at the vault — is the call payoff
(DIFFICULTY_DERIVATIVE.md §1.1). The single change relative to the bilateral option:
**`cp_key` is not the buyer's personal key; it is a pot covenant's taproot output key.**
A point is a point — the consensus opcode pays `OP_1 <cp_key32>` and never knows the
difference.

### 1.2 The N-share trick (no on-chain pro-rata math)

Tapscript cannot divide a dynamic pot among k-of-N claimants. So division is made
physical at issuance:

- `N` writer vaults of `K/N` each (identical terms, distinct `contract_id` salts),
- `N` pots — `pot_i` receives vault `i`'s cp payout,
- `N` unique sinks — `sink_i` is where a token unit is retired to redeem `pot_i`,
- exactly `N` raw token units ever (registry cap).

Each pot's covenant never needs to know its own value (unknowable at issuance — it is the
realized option payout): it only checks "this tx retires 1 token unit to `sink_i`", and the
redeemer takes whatever the pot holds. All lots are economically identical, so units stay
fungible; redemption races between holders are a nuisance (loser redeems a different pot),
never theft.

### 1.3 Worked example

`K = 3,000 TSC`, notional 10,000 → `λ = 10,000/3,000` (`lambda_q = 218453` Q16), strike
nBits committed, fixing `H = 150,000`, premium `P = 500 TSC`, `N = 100` lots of 30 TSC.

In target space the move is `(K_target − S_target)/S_target = difficulty_ratio − 1`
(DIFFICULTY_DERIVATIVE.md §1.1), so "+20% difficulty" is move `0.20` exactly:

| Outcome at H | per-lot split (vault `i`) | aggregate |
|---|---|---|
| diff ≤ strike | 30 → writer, **0 → pot_i** (zero leg skipped) | writer recovers 3,000; tokens expire worthless, no action by anyone |
| diff +20% | ≈20 → pot_i, ≈10 → writer (`clamp(λ·0.20)=⅔`, Q16-floored) | holders ≈2,000, writer ≈1,000 + the 500 premium (realized via unit sales under self-issuance; banked day-1 under the bilateral variant) |
| diff +30%+ | 30 → pot_i, 0 → writer (full clamp) | holders 3,000 (the cap) |

A holder of `k` units redeems `k` pots whenever they like, independently.

---

## 2. On-Chain Architecture

### 2.1 Series descriptor — everything derivable, committed on-chain

A canonical serialization (the **series descriptor**) commits: a `descriptor_version` byte,
option terms (strike, `fixing_height`, `settle_lock_height`, `lambda_q`, per-lot `im`,
premium, writer/issuer key), `N`, a single `series_salt`, and the derivation rules below.
**The per-lot salts are NOT stored** — committing them would be circular, since each
`salt_i = H(series_id || "lot" || i)` and `series_id = asset_id = H(tag || descriptor)`
already depends on the whole descriptor. The descriptor commits the *root* (`series_salt`)
and the *rule*; every per-lot salt, pot key, and sink key is then derived from
`series_id` after the fact (§6.1's struct comment is the authority — salts are derived,
never stored). It is:

- embedded in the ICU payload at registration (`ICU_TEXT_CHUNK`, ≤100KB; bound by
  `icu_ctxt_commit`), so any wallet reconstructs **every** address in the series from chain
  data alone;
- hashed into the asset id by convention: `asset_id = TaggedHash("TSC-OptionSeries/v1",
  descriptor)` (BIP340 tagged hash; the tag + byte layout are normative in
  `OPTION_SERIES_FREEZE.md` §2–§3). This identity is a convention the verifier recomputes
  (`optionseries.derive` / `optionseries.verify`), not a consensus-enforced binding.

`series_id = asset_id` is used as the derivation root everywhere below.

### 2.2 Lot vaults — the existing leaf, verbatim

Per lot `i`, a `DifficultyContractRecord` with `kind = DIFFICULTY_KIND_OPTION`,
`salt = H(series_id || "lot" || i)`, writer leg `im = K/N`, and **`cp_key = pot_i`'s taproot
OUTPUT key** (the NUMS_H-internal, leaf-tweaked key from §2.3). The vault leaf script is
byte-for-byte `BuildDifficultyLeafScript` (`difficulty_contract.h:266`, def
`difficulty_contract.cpp:108`):

```
<contract_id32> OP_DROP
<settle_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
<fixing_height_le4> <strike_nbits_le4> <lambda_q_le4> OP_1 <vault_im_le8>
<writer_key32> <pot_i_output_key32> OP_DIFFCFD_SETTLE
```

Internal key NUMS_H (`XOnlyPubKey::NUMS_H`); per-lot salts give distinct output keys via the
taptweak. The cooperative-close leaf (`BuildDifficultyCoopLeafScript`,
`src/wallet/difficulty_contract.h`) is **not** used for tokenized lots: its
`<cp_internal> OP_CHECKSIG` arm — which commits the *internal* coop keys
(`CoopOwnerInternal`/`CoopCpInternal`), not the tweaked output `cp_key` — is dead weight when
the buyer side is a NUMS covenant key with no signer. Instead, the lot vault is a two-leaf tree
of the **settle leaf above** plus the **token-gated writer buy-back leaf** (§8): both are built
by `CreateOptionVaultBuilder(settle_leaf, buyback_leaf)` (`src/wallet/option_series.h`), with a
matching `BuildOptionSettlementSkeleton` reconstructing the settlement control block from that
exact shape. The leaf set is recorded in the descriptor (`OptionSeriesTerms::leaf_set`), so the
vault OUTPUT key where collateral sits is reproducible from the series terms alone.

### 2.3 Pots — "anyone may sweep, iff 1 unit retires to my sink"

`pot_i` is a P2TR output: internal key NUMS_H, single leaf:

```
<tapmatch(sink_i_spk)32> <asset_id32> <0x01 00 00 00 00 00 00 00> OP_OUTPUTMATCH_ASSET
```

Operand order matches the handler (`src/script/interpreter.cpp`, `OP_OUTPUTMATCH_ASSET` at
`:1206`: amount at stacktop, then asset_id, then hash); amount is **8-byte LE raw units**; the
hash is `ComputeTapMatch(spk) = SHA256("TapMatch" || scriptPubKey)` (`interpreter.cpp:2437` — the
helper is exported, and the wallet builder calls it rather than reimplementing it). Execution
leaves exactly one true element on success. No CLTV is needed: a pot address has no UTXO until
settlement creates one, and sweeping early is impossible because there is nothing to sweep.

Properties that are load-bearing:

- **`OP_OUTPUTMATCH_ASSET` is existential** (`OutputMatches`, `interpreter.cpp:2462`): an
  output can satisfy checks from many inputs. Therefore **unique `sink_i` per lot is
  mandatory** — it is the only thing preventing one token output from opening two pots in
  one tx. (Settlement itself is safe regardless: `OP_DIFFCFD_SETTLE` uses the strict
  distinct-output matcher `VerifyDiffCfdOutputs`, `interpreter.cpp:2518`.)
- The existential behavior is *useful* within a lot: if a pot address ever accumulates more
  than one UTXO, a single token-to-sink output sweeps them all in one tx.
- `OutputMatches` skips non-spendable script families (`IsSpendableScriptFamily`,
  `interpreter.cpp:2448`); sinks are P2TR so they pass the filter.

### 2.4 Sinks — provably unspendable, per-lot

`sink_i` is a bare P2TR output key with no known discrete log and no constructible control
block: derive `x = TaggedHash("TSC-OptionSeries/sink", series_id || le32(i) || le32(ctr))`,
increment `ctr` until `x` lifts to a valid x-only point, use it **untweaked** as the output
key. (Frozen tag; lot salts use `TSC-OptionSeries/lot` — see `OPTION_SERIES_FREEZE.md` §4.) A
script-path spend would require exhibiting `(P, root)` with `Q = P + H_taptweak(P||root)·G`
for a hash-derived `Q` — a fixed-point search, infeasible. Retired units sit at sinks
forever: this is **retirement by unspendability, not burn** — `burned_total` never moves
(burning would require the ICU, §2.5), and no burn path is needed.

Cost note: each sink output must carry dust (546 sats native) under the AssetTag — redeeming
`k` lots burns `k × 546` sats of native dust. Price it into the redemption RPC's fee math.

### 2.5 Asset registration — the trust kernel

Registered via the existing `registerasset` RPC (`src/wallet/rpc/assets.cpp:2075`) with these
invariants, which together make a *live* ICU provably inert:

| Field | Value | Why (consensus anchor) |
|---|---|---|
| `issuance_cap_units` | `N` | After the issuance tx mints N, zero headroom: any further mint hits `asset-cap-exceeded`. |
| `policy_quorum_bps` | `0` | Every governance rotation (cap, icu commit/visibility, quorum itself) is consensus-rejected: `icu-immutable-rotation`, reached only via the `governance_changed` branch — which is exactly that field set. |
| `policy_bits` | `MINT_ALLOWED`, **no** `BURN_ALLOWED` | Mint needed once; burn path closed. Immutable via `core_policy_commit`. |
| `decimals` | `0` | Covenants check **raw** `AssetTag.amount`; claim unit must equal raw unit. Decimals are display-only — a nonzero value here invites a 10^d mismatch between "1 token" and "1 claim". |
| `allowed_spk_families` | include P2TR | Units live at holder P2TR addresses and at P2TR sinks. |
| `kyc_flags` | `0` | Permissionless. A regulated series can delegate compliance via `kyc_delegation`. |
| ICU payload | `canonical_text` + typed metadata bands | §2.1, §6.5; `canonical_hash` binds the operative text, `icu_ctxt_commit` the whole payload. |
| ICU bond | `Consensus::Params::AssetMinIcuBond` (5 TSC) | Consensus minimum for initial registration (`asset-bond-minimum`, on the `!had_prev` ConnectBlock path). Refundable, not sunk: tx fees of every asset-touching tx accrue to `fees_accum_sats`; at `fees_accum >= unlock_fees_sats` the bond rotates out to dust. Pre-unlock floor: `rotation_min_sats` = 95% of bond. |
| `unlock_fees_sats` | `==` ICU bond | Consensus requires `>=` bond (`asset-unlock-below-bond`); setting it equal makes the series self-recover its bond fastest. |
| ICU destination | issuer (writer) P2TR key | §2.6. The issuer self-signs mint + rotation; satisfies the ICU output-binding-sighash rule (`consensus/tx_verify.cpp`, `icu-invalid-sighash`) with one real signature. (Advanced bilateral variant: 2-of-2 writer+buyer.) |

**ICU disposal.** Consensus requires every ICU spend to create exactly one successor
IssuerReg (`asset-bond-rotation` — "dust rotation to burn address allowed" only *after* unlock;
before unlock the successor must carry `rotation_min_sats`). Default posture: the issuance tx
rotates the ICU to a successor at
the **same issuer key** with the minimum bond, and the issuer simply never spends it again —
*economically* inert by the table above (cap full + quorum zero + burn off: no spend can
mint, burn, or change governance fields). One caveat — **ticker binding is
not quorum-gated** (`ticker` is not in the `governance_changed` set), so an empty-ticker
series could have a name bound later by a plain ICU rotation — is
cosmetic, not economic, and — for the recommended sponsored-child path only — is closed by
the sponsored-child mechanism (`ICU_CHILD.md`). A low-bond child is
registered **already bound** to `ROOT.SUFFIX` — the 10,000-sat floor is available only to a
child-ticker registration carrying its parent's co-spend (ICU_CHILD §3.2) — and ticker
bindings are immutable, so such a child has no empty-ticker window to squat. This is **not** a
global root-squat fix: ICU_CHILD deliberately adds no root-squat restriction (ICU_CHILD §3.4),
so a standalone tickerless asset may still later bind an unclaimed root under current
economics — that path is accepted, not forbidden. New series should therefore register as
**sponsored children** (dust bond, ticker `ROOT.SUFFIX`) under a once-bonded brand root rather
than as standalone full-bond roots — see §9.1 for the economics. A standalone full-bond root
that genuinely wants no ticker can still rotate to a §2.4-style unspendable key once unlocked,
so "no issuer authority exists" remains a one-line audit.

### 2.6 Issuance ceremony — one registration tx, one self-signed atomic tx

**Primary model: self-issuance (single signer).** The writer is the issuer and the sole
signer. No covenant forces the mint shape and no counterparty is needed: the writer owns the
ICU, posts its own collateral, and mints all `N` units to itself, then sells them on market.
Every policy cap is trivially satisfied (§5); secondary buyers verify the confirmed history
and the on-chain descriptor (§6.5) before purchasing units (§3).

```
tx1 (registration):  registerasset → ICU @ issuer (writer) key, canonical_text + typed metadata bands (§6.5)

tx2 (issuance, self-signed):
  inputs:   ICU (issuer key, SIGHASH_DEFAULT)      ← authorizes mint + rotation
            writer funding (≥ K + fees)
  outputs:  N × lot vault_i        (K/N native each; §2.2 scripts)
            1 AssetTag output: N raw units → issuer (dust native value)
            ICU successor (IssuerReg, min bond) → issuer key   [or burn key once unlocked]
            change
```

Mint legality: the ICU is an input (`consensus/tx_verify.cpp`), `Δ=+N ≤ cap`, and the ICU input
carries the issuer's output-binding signature. There is **no premium output and no buyer
funding** — the writer's premium is realized by selling units on market, so `record_issue`
verifies the N vaults + mint amount against the descriptor but **not** a premium output
(contrast the bilateral variant). One signer means **no PSBT exchange** — the whole ceremony
is GUI-driven (§6.5).

**Advanced variant: bilateral cosign.** When a named buyer exists at issuance, the two parties
co-sign one atomic tx so the buyer locks premium-for-units at a fixed price. This reuses the
existing bilateral-option open (`difficulty.build_open` / `record_open`, `rpc/difficulty.cpp:543`)
— the inspect-and-cosign PSBT pattern incl. premium-output enforcement — generalized to N
vaults plus the mint and rotation. Registration then uses a 2-of-2(writer, buyer) ICU, and tx2
adds buyer funding (`≥ P + dust`), a `premium P → writer` output, mints the N units to the
buyer, and rotates the ICU successor back to the 2-of-2:

```
tx2 (bilateral, co-signed):
  inputs:   ICU (2-of-2, SIGHASH_DEFAULT) + writer funding (≥ K) + buyer funding (≥ P + dust)
  outputs:  N × lot vault_i + premium P → writer + N units → buyer + ICU successor → 2-of-2 + change ×2
```

### 2.7 Settlement

Unchanged from DIFFICULTY_DERIVATIVE.md: once `H` is buried `DIFFCFD_MATURITY_DEPTH` and the
CLTV opens, anyone broadcasts N settlement txs (one vault per tx — consensus §2.3 one-
difficulty-input rule), each built by `BuildOptionSettlementSkeleton` from lot `i`'s
terms, with an external fee input. Consensus recomputes the split via `ComputeDiffCfdPayout`
(`src/consensus/difficulty_cfd.cpp:34`) — a **clamped exact floor with a 546-sat dust-snap**
(`difficulty_cfd.cpp:84`), **not** a naive `floor(f_loss·im)`, and the loser is selected by
the leg's `loss_dir` byte; the wallet builder and the Python test mirror MUST replicate this
arithmetic exactly or the settlement tx fails `OP_DIFFCFD_SETTLE`'s exact-amount check
(`VerifyDiffCfdOutputs`). ITM it sends that amount to `pot_i` as a bare `OP_1 <pot_i>`
output; OTM omits the zero leg so pots receive nothing and the series dies quietly. Any single
holder has the incentive to settle all N (their pots are unpayable until settled).

Dust interaction: a lot's ITM payout below 546 sats dust-snaps to the writer
(`difficulty_cfd.cpp:84-93`). Choose `N` so the smallest payout you care about clears dust
per-lot (at 30 TSC lots this only bites within ~0.002% of the strike).

### 2.8 Redemption

A holder of `k` units (one tx, batched):

```
inputs:   pot_{i1..ik}  (witness = [pot leaf, control]; no signatures)
          holder token UTXO (m ≥ k units)
          native fee input
outputs:  k × { sink_ij : 546 sats + AssetTag(asset_id, 1 unit) }
          token change (m − k units) → holder
          native sweep (Σ pot values − fees) → holder
```

Each pot input's leaf finds its own sink output; unique sinks make the accounting
one-token-one-pot (§2.3). Asset conservation holds (Δ=0, no ICU needed). Pots are
interchangeable — the RPC just picks any k unspent ones.

---

## 3. Trust Model

After tx2 confirms there is **no issuer authority, no oracle, no custodian, and no signing
dependency** anywhere in the lifecycle:

| Stage | Who must be honest | Enforced by |
|---|---|---|
| Issuance | nobody — buyers verify before buying units | self-signed atomic tx; `canonical_text` + typed metadata bands bound in the ICU payload (§6.5); the bilateral variant adds inspect-then-cosign |
| Supply | nobody | cap + quorum-zero + no-burn registry invariants (§2.5), consensus-checked every block |
| Custody of collateral | nobody | NUMS-internal vaults; only the settle covenant can spend |
| Settlement amounts | nobody | `OP_DIFFCFD_SETTLE` recomputes from chain nBits; broadcaster is a courier |
| Settlement liveness | any one keeper | signatureless leaf; 100-block burial then open forever |
| Redemption | nobody | pot covenant + unique sinks |

What a verifier (wallet listing the asset) must check, all from chain data: descriptor hash
== asset_id, registry entry matches §2.5 invariants, `issued_total == cap == N`, the N vault
outpoints from tx2 match the descriptor-derived scripts/amounts, each vault's `cp_key`
equals the derived `pot_i` output key. One pass at listing time, O(N). **Premium is NOT in this
set** — under self-issuance it is reference/display economics realized through unit sales, so a
verifier never checks it against an on-chain transfer (only the bilateral variant has a premium
output, §6.1).

Residual disclosures for holders: payout is capped at `K` (covered call, not a future);
writer default risk is zero but writer *upside participation* above the cap doesn't exist;
token decimals are 0 by construction.

---

## 4. Why No New Consensus — touchpoint audit

Every consensus rule the feature touches is a pre-existing one; the table maps each to how the
option layer satisfies it.

| Consensus rule | How the option layer satisfies it |
|---|---|
| Mint requires ICU input + `MINT_ALLOWED` (`consensus/tx_verify.cpp:604`) | tx2 spends the ICU |
| ICU input needs output-binding sig (`consensus/tx_verify.cpp`, `icu-invalid-sighash`) | issuer-key Schnorr, SIGHASH_DEFAULT (2-of-2 in the bilateral variant) |
| ICU spend ⇒ exactly one successor IssuerReg (`asset-bond-rotation`) | rotation output in tx2 |
| `unlock_fees_sats ≥ bond` at registration (`asset-unlock-below-bond`) | minimal bond |
| Issuance cap (`asset-cap-exceeded`) | cap == N, fully minted |
| Quorum-zero immutability (`icu-immutable-rotation`) | `policy_quorum_bps = 0` |
| One difficulty input per tx | one settle tx per lot |
| `OP_DIFFCFD_SETTLE` exact outputs / distinct matcher | pays `OP_1 <pot_i>` |
| `OP_OUTPUTMATCH_ASSET` existential semantics | unique sinks per lot (design discipline) |
| Script cache bypass for chain-reading leaves | settlement txs only |

---

## 5. Policy / Standardness Analysis

- **tx2 (issuance)**: contains **zero** OUTPUTMATCH opcodes (the ICU path is a plain key-path spend — issuer key, or 2-of-2 in the bilateral variant;
  vault outputs don't execute scripts at creation), so `MAX_COVENANT_TX_OUTPUTS{128}` does
  not apply (`policy.cpp:368` gates it on `TxHasOutputMatch`). ~N+5 outputs of plain P2TR —
  standard. N in the low hundreds is fine; beyond that, vault creation splits across
  follow-up txs (only the mint itself needs the ICU input).
- **Settlement txs**: one covenant input, ≤4 outputs each. Standard under standard relay.
- **Redemption txs**: each pot input executes exactly 1 OUTPUTMATCH
  (within `MAX_OUTPUTMATCH_PER_INPUT{8}`); the tx *does* contain OUTPUTMATCH so the 128-output
  cap applies, giving `k ≤ ~120` lots per redemption tx; the RPC batches above that.
- **Witness items**: pot leaf pushes are 32/32/8 bytes, under
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE{80}`.

---

## 6. Wallet Layer

The feature lives in `src/wallet/option_series.{h,cpp}` (derivation + covenant builders) and
`src/wallet/rpc/option_series.cpp` (RPC surface), mirroring the difficulty-contract layering and
reusing `difficulty_contract.{h,cpp}` for the vault leaf.

### 6.1 Data structures

```cpp
//! Immutable series parameters. The fixed binary SerializeOptionDescriptor() of these fields IS the
//! §2.1 descriptor that asset_id commits to; the SERIALIZE_METHODS form is the wallet-persistence
//! encoding (and grows the trailing `direction` byte only for descriptor_version >= 2).
struct OptionSeriesTerms {
    uint8_t  descriptor_version{kOptionDescriptorVersion};
    uint8_t  issuance_mode{OPTION_ISSUANCE_SELF};   // self-issuance (primary) | bilateral cosign
    uint8_t  leaf_set{OPTION_LEAFSET_SETTLE_BUYBACK}; // vault leaf set (settle + buy-back)
    XOnlyPubKey writer_key{};              // issuer/writer raw signable key: payout output key AND buy-back signer
    uint32_t strike_nbits{0};
    uint32_t fixing_height{0};
    uint32_t settle_lock_height{0};
    uint32_t lambda_q{0};                  // Q16
    CAmount  lot_im_sats{0};               // per-lot IM = K/N
    uint32_t lot_count{0};                 // N
    //! Premium is NEVER part of backing verification (§3 checks vaults + mint + cap, never premium).
    //! Under self-issuance this is a display/listing reference price only — never an on-chain transfer,
    //! since the writer realizes it through later unit sales. Only the bilateral variant (§2.6) enforces
    //! an upfront buyer→writer payment.
    CAmount  reference_premium_sats{0};
    uint256  series_salt{};                // randomizes the series (and so asset_id)
    uint8_t  direction{OPTION_DIRECTION_CALL}; // call (writer short) | put (writer long); descriptor byte only when v >= 2
    // asset_id, per-lot salts, pot/sink keys are all DERIVED, never stored ad hoc.
};

//! Persisted record (DBKeys::OPTION_SERIES{"optseries"}, src/wallet/walletdb.cpp).
struct OptionSeriesRecord {
    uint256 series_id{};                   // == asset_id == ComputeOptionSeriesId(terms)
    OptionSeriesTerms terms;
    COutPoint icu_outpoint{};              // current ICU successor (after the issuance tx)
    uint256 register_txid{}, issue_txid{};
    std::vector<COutPoint> lot_vaults;     // N funded lot-vault outpoints (from the issuance tx)
    // pots/sinks recomputed on demand from terms (no storage drift).
};
```

On load, `ValidateOptionSeriesRecord` re-derives `series_id == ComputeOptionSeriesId(terms)`,
re-checks `terms` against `ValidateOptionSeriesTerms`, and requires `lot_vaults` to be exactly
`lot_count` non-null, non-duplicate outpoints, so a tampered record fails closed
(`LoadOptionSeriesRecords`, `src/wallet/walletdb.cpp`).

### 6.2 Builders (pure, unit-testable)

All builders are self-deriving from `(terms, series_id, lot_index)` and verify each funded UTXO's
scriptPubKey rather than trusting ad-hoc leaves (`src/wallet/option_series.h`):

- `ComputeOptionSeriesId(terms)` — tagged hash (`TSC-OptionSeries/v1`) of the canonical
  descriptor; `SerializeOptionDescriptor` / `ParseOptionSeriesDescriptor` are the fixed binary
  encode/decode.
- `DeriveOptionLotSalt(series_id, i)` — `H(series_id || "lot" || i)` (tag `TSC-OptionSeries/lot`).
- `DeriveOptionSink(series_id, i)` — §2.4 counter-loop to a valid x-only key (tag
  `TSC-OptionSeries/sink`); returns the key and the counter used.
- `BuildOptionPotLeaf(asset_id, sink_spk)` — §2.3 script, hash via the **exported**
  `ComputeTapMatch`.
- `BuildOptionBuybackLeaf(writer_key, asset_id, sink_spk)` — the token-gated writer buy-back leaf
  (§8).
- `CreateOptionPotBuilder(pot_leaf)` — TaprootBuilder, NUMS_H internal; exposes the pot output
  key for use as the lot's `cp_key`.
- `DeriveOptionLot(terms, series_id, i)` — the per-lot derivation (salt, pot key, sink) that the
  lot vault's `BuildDifficultyLeafScript` consumes; the leaf script is reused verbatim.
- `CreateOptionVaultBuilder(settle_leaf, buyback_leaf)` — the two-leaf lot-vault TaprootBuilder
  (settle + buy-back, NUMS_H internal), with `BuildOptionSettlementSkeleton` reconstructing the
  settlement control block from that exact leaf set. This is option-specific (not
  `CreateDifficultyVaultBuilder`, which finalizes a settle+coop tree): the leaf set is recorded
  in `terms.leaf_set`, so the merkle root, taptweak, and vault output key are reproducible from
  the terms.
- `BuildOptionRedemption(terms, lots[], token_inputs)` — §2.8 skeleton incl. pot witnesses
  `[leaf, control]` and the per-sink AssetTag outputs (the plaintext 2-arg `BuildAssetTagTlv`,
  shared in `src/wallet/contract.h`, covers the 1-unit sink tags).
- `BuildOptionBuyback(terms, lot_index, ...)` — the writer buy-back spend (§8), retiring one unit
  to `sink_i` to reclaim a lot's collateral early.

### 6.3 RPCs

The builder/issuance RPCs are wallet RPCs (`src/wallet/rpc/option_series.cpp`, registered in
`src/wallet/rpc/wallet.cpp`); the two verifier RPCs are node-level (`src/rpc/option_series.cpp`)
and run on any node with no wallet or chain state for `derive`:

| RPC | Does |
|---|---|
| `optionseries.derive` | Read-only, deterministic: from terms alone, recompute `asset_id == H(descriptor)` and re-derive every lot vault / pot / sink. The verifier's recompute tool (§3). |
| `optionseries.verify` | Pre-purchase fraud check (§3): given the `asset_id` a buyer intends to purchase and the series' published terms (raw descriptor, on-chain `TSC-ICU-META-1` band, or terms object), confirms `asset_id` is the tagged hash of the descriptor — a swapped or forged term set cannot match — and returns the decoded terms plus the backing (N lot vaults at the per-lot IM) the buyer must then confirm is funded on-chain. |
| `optionseries.build_register` | Registers the asset shell for a series (self-issuance) as a sponsored child `ROOT.SUFFIX` under an existing bonded parent root, via the `sponsorchildasset` path. It creates an issuer-key child ICU carrying a user-legible `canonical_text` terms summary plus the typed `TSC-ICU-META-1` metadata band (§6.5). There is no standalone-root option-series path. |
| `optionseries.build_issue` | Self-signed tx2: mints all N units to the writer and funds the N derived lot vaults (`lot_im_sats` each) in one transaction (composing `mintasset`), plus the ICU rotation — the issuer signs alone, no PSBT exchange. |
| `optionseries.record_issue` | Persists the series record after the issuance tx confirms; resolves the N lot-vault outpoints from the confirmed tx by their derived scripts and verifies the mint amount against the descriptor. |
| `optionseries.list` | Lists the series persisted in this wallet (the in-memory map repopulated from disk on load), including each series' registry-invariant / listability state (§3 verifier checklist) — what an exchange consults before listing. |
| `optionseries.build_settlement` | Builds the settlement transaction for ONE lot vault (keeper-driven, signatureless covenant) via `BuildOptionSettlementSkeleton`, once the lot's fixing height is buried by `DIFFCFD_MATURITY_DEPTH` and the settle CLTV has opened. |
| `optionseries.build_redeem` | k-lot redemption tx (§2.8): spends each named pot by retiring exactly one unit to that lot's unique sink, batched at the policy cap. |
| `optionseries.build_buyback` | The writer's early unwind for ONE lot vault: spends the vault via its buy-back leaf — an output-committing covenant plus a writer signature — retiring one unit to the lot's sink to reclaim that collateral early (§8). |

### 6.4 Persistence / registry plumbing

Series records persist under WalletDB key `optseries` (`DBKeys::OPTION_SERIES`), written by
`WalletBatch::WriteOptionSeries` and reloaded by `LoadOptionSeriesRecords` beside the
difficulty-contract load hook (`src/wallet/walletdb.cpp`). Lot vaults register covenant-only in
the vault registry (the `VaultLeafDescriptor::IsCovenantOnly` path); pots are NOT wallet vaults —
holders discover them from the descriptor and the UTXO set at redemption time.

### 6.5 Issuer flow + ICU termsheet

The single-signer model collapses creation and position-opening into one actor's cockpit. The
issuer (writer) is the counterparty who posts the IM, so "make the asset" and "open the
position" are the same ceremony — and they deserve a dedicated surface rather than the generic
asset-registration control, which only covers the registration step.

The single-signer model collapses creation and position-opening into one issuer cockpit: the
Qt wallet exposes the series under a dedicated flow (`src/qt/treasurypage.cpp`,
`src/qt/walletmodel.cpp`) that walks the issuer through the terms, the required sponsored-child
namespace, the terms document, and a review-and-issue step, driving `optionseries.derive` →
`optionseries.build_register` → `optionseries.build_issue`. The bilateral variant (§2.6)
surfaces the two-party PSBT handshake as an advanced option.

**ICU payload layout — operative text vs. machine metadata.** The ICU payload
(`src/assets/icu_payload.h`) is **plaintext** for a tradeable option — NOT keywrapped (it must
be publicly verifiable; the `MAX_ICU_KEYWRAP_*` confidential path is unused) — retrievable by any
wallet via `geticupayload_historical` / `geticupayload_prior` (`src/rpc/rawtransaction.cpp`). It
carries two distinct, non-interchangeable slots:

- **`canonical_text`** (bound by `canonical_hash = SHA256(canonical_text)`, `icu_payload.h`) →
  the **operative** human option-terms document — the actual binding contract a wallet/legal
  renderer shows as-is. This is the authority for the human terms. Its inline ICU-context block
  is gated by the strict `ValidateIcuContext` allow-list (`{spec, parse_version, acceptance,
  bodies}` only; `src/assets/icu_payload.cpp`), an anti-bifurcation hardening separate from the
  machine bands below.
- **`metadata`** (raw bytes — `icu_payload.h`) → the **machine** bands, a canonical-JSON
  `TSC-ICU-META-1` container.

**The `metadata` typed-band container.** `BuildOptionSeriesIcuMetadata`
(`src/wallet/option_series.cpp`) produces the container via the shared canonical-JSON band
encoder `CanonicalizeIcuBandJson` (`src/assets/icu_payload.cpp`), with deterministic encoding so
third-party renderers (wallets, explorers, the legal renderer) parse it identically:

```
metadata = { "spec": "TSC-ICU-META-1",
             "optseries": { "spec":"TSC-ICU-OPTSERIES-1", "parse_version":1,
                            "descriptor": "<EXACT descriptor hex>" },   // asset_id-bound
             "termsheet": { "spec":"TSC-ICU-TERMSHEET-1", "parse_version":1, … } }  // non-operative summary
```

Metadata parsing has **no on-chain enforcement**: trust derives from the commitments (`asset_id`,
`icu_ctxt_commit`, `canonical_hash`) and the verifier recompute, never from "the node validated
it." The `optseries` band carries the **exact descriptor bytes** — the same byte string fed to
`asset_id = H(tag || descriptor)`, not a semantically-equivalent re-encoding — so a verifier can
recompute `asset_id` and re-derive every vault/pot/sink. `optionseries.verify` validates the
container fail-closed: it re-canonicalizes the `TSC-ICU-META-1` bytes, checks the `spec` strings,
and extracts the `TSC-ICU-OPTSERIES-1` descriptor (`src/wallet/option_series.cpp`). The
**termsheet band** is a non-operative machine index/summary auto-derived from the §2.1 terms
(option kind, strike, fixing/settle heights, λ, lot count, per-lot IM, reference premium, payout
cap, and the §3 disclosures: covered call/put not a future, zero writer-default risk, decimals 0)
so it cannot drift from the terms. **Hard boundary:** the operative terms live only in
`canonical_text`; the termsheet band is **never** a second binding document.

### 6.6 Registration-helper reuse

The series registration path reuses the asset-registration machinery — `BuildIssuerRegV1`,
`BuildAssetRegistrationTLVs`, the keywrap-aware `BuildAssetTagTlv`, `ResolveAssetIdOrTicker`, and
the `sponsorchildasset` parent-rotation + child-IssuerReg assembly (`src/wallet/rpc/assets.cpp`)
— rather than reimplementing it, so an option series is registered as an ordinary sponsored
child. The redemption sink tags use the 2-arg plaintext `BuildAssetTagTlv`
(`src/wallet/contract.h`).

---

## 7. Tests

**Unit (`src/wallet/test/option_series_tests.cpp`, `option_series_wallet_tests.cpp`):**

1. Descriptor round-trip; `series_id` stability; sink derivation determinism + validity.
2. Pot leaf through real `EvalScript` + `VerifyScript`: a sweep WITH the 1-unit-to-`sink_i`
   output passes; without it fails; wrong sink fails; wrong asset fails; amount 2 fails.
3. Cross-lot double-redeem: one tx spending `pot_1`+`pot_2` with a single token output satisfies
   exactly one leaf (unique sinks); with both sink outputs both pass.
4. The lot vault settles through consensus with `cp_key` = pot output key.

**Functional (`test/functional/feature_option_tokenization.py`)**, under standard relay,
mirroring `feature_difficulty_derivative_wallet.py`: register → issue (self-signed, mint to
issuer) → an extra mint is rejected (`asset-cap-exceeded`) and a governance rotation is rejected
(`icu-immutable-rotation`) → trade units to a third wallet → mine past fixing → settle all lots
ITM (payout cross-checked against a Python mirror of `ComputeDiffCfdPayout`) → redeem one lot from
each of two wallets → double-redeem and tokenless-sweep are rejected → OTM variant: pots empty,
writer whole; with a node restart mid-series exercising record persistence. The bilateral variant
issues via the two-party cosign and asserts the enforced `premium P → writer` output.

Sponsored-child scenarios (parent co-spend, `ROOT.SUFFIX` assembly, one-hop-grammar rejection,
the option-specific client-side field checks, the listability gate) reuse the sponsored-child
consensus feature (`test/functional/feature_icu_child.py`) and are specified for the option layer
in §9.1.1.

---

## 8. Properties and edge cases

- **Writer buy-back leaf (pre-maturity exit).** Each lot vault carries, alongside its settle
  leaf, a token-gated writer buy-back leaf that allows an early unwind with no new consensus:

  ```
  <writer_key> OP_CHECKSIGVERIFY <tapmatch(sink_i)> <asset_id> <0x01..> OP_OUTPUTMATCH_ASSET
  ```

  The writer repurchases units on the market, retires one to `sink_i`, and reclaims that lot's
  collateral early. The leaf is built by `BuildOptionBuybackLeaf` and spent via
  `BuildOptionBuyback` / `optionseries.build_buyback`; its presence is committed in
  `OptionSeriesTerms::leaf_set`, so the vault address derives from the terms.
- **`ComputeTapMatch` is not duplicated** — the pot/buy-back builders call the interpreter's
  exported helper directly, and a unit test pins the tagged-hash vector.
- **Premium is series-level** — one output, not per-lot; `record_issue` checks it once, and only
  in the bilateral variant.
- **Sink dust accumulation** is by design: redeeming `k` lots burns `k × 546` sats of native
  dust, priced into the redemption RPC's fee math.
- **ICU bond economics.** The initial bond floor is consensus (`Consensus::Params::AssetMinIcuBond`,
  5 TSC) and refundable. `fees_accum_sats` is fed by the full native fee of every tx touching the
  asset (AssetTag/IssuerReg in inputs or outputs, equal-shared across touched assets): issuance,
  token trades, and redemptions all count; native-only settlement txs do not. A series that
  generates 5 TSC of cumulative such fees unlocks its bond for dust rotation. For amortizing the
  bond across many series, see §9.1.
- **Quorum-zero is permanent** — there is no recovery path for a misconfigured series except
  issuing a new one, so `optionseries.build_register` validates the descriptor exhaustively.
- **Descriptor and band encoding are fixed.** `SerializeOptionDescriptor` /
  `ParseOptionSeriesDescriptor` define the canonical binary layout that `asset_id = H(descriptor)`
  commits to; the `TSC-ICU-META-1` / `TSC-ICU-OPTSERIES-1` / `TSC-ICU-TERMSHEET-1` band schemas
  share the same deterministic canonical-JSON encoding (`CanonicalizeIcuBandJson`); and the leaf
  set is part of the descriptor. A third-party wallet reproduces the descriptor bytes exactly to
  recompute `asset_id` and re-derive the N addresses. The byte-level layout is normative in
  `OPTION_SERIES_FREEZE.md`.

## 9. Composition over root-sponsored children

### 9.1 Bond amortization for listed chains

A listed option chain composes many series under one bonded brand root. One asset per series at a
flat `AssetMinIcuBond` (5 TSC) would make a 40-series chain cost 200 TSC of locked bond; the
sponsored-child mechanism unbundles what the bond actually prices. Bytes are already priced by
vbytes (the ICU payload pays block space like any tx data); what is left is the **root ticker
namespace** and **ongoing issuer authority**.

The mechanism is the generic one in `ICU_CHILD.md` — consensus core, parser, mempool mirror,
lookup RPCs, the `sponsorchildasset` wallet RPC, the `registerasset` root-only alignment, and the
Qt registration flow. Option series compose over it as ordinary low-bond children:

- **Dotted ticker grammar.** Exactly one child level: `ROOT.SUFFIX`, both sides the existing
  root grammar (`[A-Z][A-Z0-9]{2,10}`), total ≤ 23 bytes (`src/assets/asset_parser_v1.cpp`). The
  parser has no block-height context, so it does not gate on activation — it accepts root or
  one-hop child grammar; any height-aware accept/reject lives in `validation.cpp`. A dotted
  ticker can never sponsor a further child (one hop, enforced by grammar). Global uniqueness of
  the full string rides the existing ticker binding index.
- **Child bond floor.** `Consensus::Params::SponsoredChildMinIcuBond = 10,000 sats`. An
  initial IssuerReg carrying a child ticker may meet the bond rule at this floor instead of
  `AssetMinIcuBond` — but only with a valid parent sponsorship proof.
- **Parent sponsorship.** The child registration co-spends the current ICU UTXO of the asset
  bound to `ROOT`, whose prevout value is `>= AssetMinIcuBond`. The parent's output-binding
  signature and its forced successor rotation are the *existing* ICU rules; no parent pointer,
  child counter, or persistent parent-child state is added. Sponsorship is a stateless co-spend
  proof at the moment the child ticker is bound — not on later child rotations.

A low-bond child is treated as an ordinary asset that simply paid a smaller initial bond, and
option inertness is proven at the **product layer** rather than with a consensus class:

- supply inertness (cap full + quorum zero + burn off) is the same registry-field +
  confirmed-issuance argument used for full-bond series (§2.5, §3) — it never depended on the
  bond size;
- for the sponsored-child path, the root-squat caveat is closed structurally: the 10,000-sat
  floor is available only to a registration that is *already* bound to `ROOT.SUFFIX` with a
  parent co-spend, and ticker bindings are immutable, so such a child has no empty-ticker window
  to later squat a root name. This is deliberately **not** a global root-squat restriction: a
  standalone tickerless asset may still bind an unclaimed root later under current economics —
  accepted, not forbidden;
- the option-specific fields (`MINT_ALLOWED`, `decimals = 0`, `issuance_cap_units = N`,
  `policy_quorum_bps = 0`, no burn, P2TR allowed, descriptor commitment present) are checked
  **client-side** in `optionseries.build_register` and re-checked by `optionseries.verify` / any
  verifier from chain data (§3, §9.1.1) — product invariants, not a consensus predicate.

**Why this is not a spam-filter bypass** — every scarce resource keeps exactly one price, and
authorization is re-presented at each privileged act rather than remembered (no persistent
parent pointer, no counters, no new registry fields):

| Resource | Price | Mechanism |
|---|---|---|
| Root ticker | full bond | full-bond root registration, unchanged |
| Sub-namespace | parent's signature | parent co-spend, DNS-style |
| Block/registry bytes | vbytes | already priced; no double charge |
| Sponsorship depth | one hop, by grammar | namespaced = exactly `ROOT.SUFFIX`; dotted tickers can never parent |
| Anti-spam child cost | 10,000 sats | `SponsoredChildMinIcuBond`, far below the full bond |

**Audit note — a child is not zero-trust until its cap is filled.** A dust child with
`MINT_ALLOWED` and `issued_total < cap` retains **bounded mint authority**: consensus only stops
minting above the cap (`asset-cap-exceeded`), and any spend of its ICU can mint within the
remaining headroom (`consensus/tx_verify.cpp`). That is the intended shape for the option product
(the issuance ceremony mints exactly N), but the §3 verifier checklist is mandatory, not
advisory: a series is zero-trust/listable only after `issued_total == cap == N` AND the N backing
lots are verified on-chain. An exchange that lists a sponsored child before its cap is filled is
trusting the ICU holders.

Children per root are unbounded: the spam that remains is self-attributed — a parent signing junk
into `ACME.*` vandalizes only its own namespace — and entry bytes pay vbytes plus the 10,000-sat
floor.

**Economics for a listed chain**: register the `ACME` root once at 5 TSC (refundable via fee
accrual as the chain trades), then every series is `SponsoredChildMinIcuBond` + vbytes with a
real ticker — `ACME.C150K`, `ACME.P150K`, next strike, next expiry — each a generic child whose
lineage is signed by the brand that owns the root, each proven inert from its own registry fields
and confirmed issuance.

#### 9.1.1 Wallet / RPC / Qt integration over the child mechanism

The option layer adds **no new consensus** — it reuses the shared `sponsorchildasset` path and
layers product-specific client-side checks. This subsection is the bridge from the §6.3 RPC
surface to that mechanism.

**`optionseries.build_register` is sponsored-child only.**

- Params: `OptionSeriesTerms`, `root_ticker`, `suffix`, and optional `parent_icu_outpoint` /
  child bond / fee controls. It reuses the `sponsorchildasset` path rather than reimplementing
  the parent rotation. It produces ONE tx that:
  1. spends the parent ICU and recreates it as a byte-identical successor (the parent's forced
     `asset-bond-rotation`);
  2. creates the child IssuerReg at the `SponsoredChildMinIcuBond` floor (10,000 sats), ticker
     `ROOT.SUFFIX`;
  3. sets the child ICU destination to the **issuer (writer) key** that the §2.6 self-signed
     `build_issue` tx will spend (the **writer+buyer 2-of-2** in the bilateral variant).
  - The option layer then applies its **product-specific client-side checks** before broadcast
    — the same fields a verifier re-derives from chain data (§3): `policy_bits == MINT_ALLOWED`,
    `decimals == 0` explicitly (not `0xFF`), `issuance_cap_units == N`, `policy_quorum_bps == 0`,
    no burn policy, P2TR allowed, descriptor commitment present, and `unlock_fees_sats >=` the
    child bond. These are product invariants, not a consensus class.
  - `sponsorchildasset` returns raw hex (and broadcasts on request) and needs the parent ICU
    owner's output-binding signature for the co-spend (`consensus/tx_verify.cpp`).
- Consensus permits several children under one parent co-spend (the sponsorship proof is per
  root, not per child output), while `sponsorchildasset` registers one child per call, so a
  strike/expiry ladder is registered one child at a time.

**`optionseries.list` / `optionseries.verify` — listability gate.** For a sponsored child the
listability state is `registered-not-listable` until `issued_total == cap == N` AND the N backing
lots verify on-chain (§9.1 audit note + §3 checklist). Full-bond roots are unaffected.

**Functional tests.** The generic consensus cases (parent co-spend, `ROOT.SUFFIX` assembly,
no-parent / wrong-root / below-bond / one-hop-grammar / duplicate rejections, child rotation and
cap) live in `test/functional/feature_icu_child.py`; the mechanism is a pure relaxation active
from genesis on upgraded nodes, with no versionbits gate. `feature_option_tokenization.py` adds
the option layer over them:

| Scenario | Expect |
|---|---|
| root registers full-bond | accept (baseline) |
| series dust-registers as a child under root (parent co-spend, `ROOT.SUFFIX`) | accept |
| `build_register` with a non-option field (quorum≠0 / burn bit / decimals≠0 / cap=0) | refused client-side before broadcast |
| child issue mints exactly N, then a further mint | accept, then `asset-cap-exceeded` |
| `optionseries.verify` on a child before cap fill | `registered-not-listable`; listing flagged unsafe |
| `optionseries.verify` after cap fill + N lots verified on-chain | `listable=true` |

**Qt** — reuses the child registration UI rather than a parallel implementation
(`src/qt/treasurypage.cpp`, `src/qt/walletmodel.cpp`):

- **Create chain root** — one-time per brand: the asset registration form in `Standalone root`
  mode registers the full-bond root ICU.
- **Add series under root** — the option series flow reuses the same `Sponsored child`
  registration control: the parent dropdown (wallet-controlled roots whose current ICU is
  spendable and `>= AssetMinIcuBond`), the inherited `ROOT.SUFFIX` ticker preview, the child bond
  defaulting to 10,000 sats, and the parent-signature step. It drives the shared
  `sponsorchildasset` path and shows the post-registration state *"registered — not listable
  until issued & backed."*

**What the class generalizes.** This is not option-specific; it is **root-sponsored,
externally-verifiable claims** (`ICU_CHILD.md` is the generic mechanism). Anything finite-supply,
capped, non-governed, and externally verifiable after issuance lives under one bonded root: option
chains, covered warrants, fully-collateralized forwards, prediction-market complete sets,
fixed-vault tranches/coupons, closed-end fund vintages. It does NOT extend to open-ended funds,
mutable/KYC assets, or margined forwards with ongoing obligations — those need a full bond or new
consensus machinery.

## 10. Source Reference Map

| Concern | File | Anchor |
|---|---|---|
| Settle opcode + distinct outputs | `src/script/interpreter.cpp` | `OP_DIFFCFD_SETTLE` (1274), `VerifyDiffCfdOutputs` (2518) |
| OUTPUTMATCH + TapMatch + family gate | `src/script/interpreter.cpp` | `OP_OUTPUTMATCH_ASSET` (1206), `ComputeTapMatch` (2437), `IsSpendableScriptFamily` (2448), `OutputMatches` (2462) |
| Payout math + dust-snap | `src/consensus/difficulty_cfd.cpp` | `ComputeDiffCfdPayout` (34), dust-snap (84) |
| Option kind (terms/validation) | `src/wallet/difficulty_contract.{h,cpp}` | `DIFFICULTY_KIND_OPTION` terms + validation |
| Difficulty vault leaf / coop leaf | `src/wallet/difficulty_contract.h` | `BuildDifficultyLeafScript`, `BuildDifficultyCoopLeafScript` |
| Option-series builders | `src/wallet/option_series.{h,cpp}` | `ComputeOptionSeriesId`, `SerializeOptionDescriptor`, `DeriveOptionSink`, `BuildOptionPotLeaf`, `BuildOptionBuybackLeaf`, `CreateOptionVaultBuilder`, `BuildOptionSettlementSkeleton`, `BuildOptionRedemption`, `BuildOptionBuyback`, `BuildOptionSeriesIcuMetadata` |
| Option-series wallet RPCs | `src/wallet/rpc/option_series.cpp` (registered `src/wallet/rpc/wallet.cpp`) | `optionseries.build_register`/`build_issue`/`record_issue`/`list`/`build_settlement`/`build_redeem`/`build_buyback` |
| Option-series verifier RPCs | `src/rpc/option_series.cpp` | `optionseries.derive`, `optionseries.verify` |
| Option-series persistence | `src/wallet/walletdb.cpp` | `DBKeys::OPTION_SERIES` (`optseries`), `WriteOptionSeries`, `LoadOptionSeriesRecords` |
| Mint/burn authorization + ICU sighash | `src/consensus/tx_verify.cpp` | mint+`MINT_ALLOWED` (604), `icu-invalid-sighash` |
| Registry reject codes | `src/validation.cpp` | `asset-unlock-below-bond`, `asset-bond-rotation`, `icu-immutable-rotation`, `asset-cap-exceeded` |
| Relay policy caps | `src/policy/policy.h` | `MAX_COVENANT_TX_OUTPUTS`, `MAX_OUTPUTMATCH_PER_INPUT`, `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE` |
| Asset registration RPC | `src/wallet/rpc/assets.cpp` | `registerasset` (2075), `sponsorchildasset` (1702) |
| ICU payload struct (slots) | `src/assets/icu_payload.h` | `canonical_hash`, `canonical_text`, `metadata` |
| ICU context allow-list + band encoder | `src/assets/icu_payload.cpp` | `ValidateIcuContext` (249), `CanonicalizeIcuBandJson` (469) |
| ICU payload retrieve | `src/rpc/rawtransaction.cpp` | `geticupayload_historical` (1111), `geticupayload_prior` (1196) |
| Sponsored-child consensus core | `src/validation.cpp`, `src/assets/asset.cpp`, `src/assets/asset_parser_v1.cpp` | dotted `ROOT.SUFFIX` grammar (`asset.cpp:29`), `SponsoredChildMinIcuBond`, co-spend proof — see `ICU_CHILD.md` |
