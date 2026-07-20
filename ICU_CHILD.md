# Sponsored ICU Children

Generic root-sponsored child assets with namespaced tickers such as `ACME.C150K`.

This document supersedes the sealed-child design in `OPTION_TOKENIZATION.md` section 9.1.
The child mechanism is deliberately simpler: a bonded root ticker may sponsor low-bond
children in its own namespace. Children are otherwise normal ICU assets.

The scope here is the generic root-sponsored child mechanism: the consensus core
(`SponsoredChildMinIcuBond`, the shared ticker helpers, dotted-ticker parser support, the
`ConnectBlock` parent-sponsorship proof and child bond floor, and the mempool policy
mirror), the `asset_id`-or-ticker lookup RPC paths, the `sponsorchildasset` wallet RPC, the
root-only alignment of `registerasset`, and the Qt registration-mode + parent-dropdown flow.

The downstream option product layer — `optionseries.build_register` / `.derive` / `.verify`
and the issuance / settlement / redemption machinery — composes *over* this mechanism as
ordinary low-bond children, not via the superseded sealed-child consensus class. It is
documented by `OPTION_TOKENIZATION.md`. The option-layer references in §6.3 and §7.2 below
pin the contract that layer honors; they are not part of the generic child consensus rule.

## 1. Goal

Allow a fully-bonded root asset to create many child assets under `ROOT.SUFFIX` without
requiring each child to post `Consensus::Params::AssetMinIcuBond`.

The scarce object is the root namespace. The parent already paid for it. A child ticker
only consumes that parent's own namespace, and cannot collide with or steal any other
ticker because ticker bindings remain globally unique.

This is not option-specific. Option series are the first consumer, but the rule is generic:

- option chains: `ACME.C150K`, `ACME.P150K`;
- dated tranches or coupons;
- prediction market outcomes;
- any finite or governed asset a root issuer wants to publish under its own namespace.

## 2. Consensus Background

The code separates the one-time initial bond floor from ongoing asset behavior.

- `AssetMinIcuBond` is checked only for initial registration, on the `!had_prev` path in
  `src/validation.cpp` (reject code `asset-bond-minimum`).
- ICU rotations use `rotation_min_sats`, seeded to 95% of the initial bond and preserved
  until unlock.
- Unlock is fee-metered: once `fees_accum_sats >= unlock_fees_sats`, the rotation floor
  drops to dust.
- Every IssuerReg output must satisfy `unlock_fees_sats >= out.nValue`.
- Mint/burn authority is enforced by `Consensus::CheckTxInputs`: mint requires an ICU
  input and `MINT_ALLOWED`; burn requires an ICU input and `BURN_ALLOWED`.
- After first issuance, core policy fields are immutable under `policy-core-changed`.
- Cap, quorum-zero governance, ticker immutability, and decimals immutability are
  independent of bond size.

Because of this, a low-bond child does not need a special sealed consensus class. A product
that needs inert behavior sets the normal registry fields accordingly and verifiers check
them. For option tokenization that means `cap=N`, `decimals=0`, `quorum=0`, no burn policy,
and confirmed issuance of exactly `N` units.

## 3. Consensus Rule

A root-sponsored child path governs initial registration and ticker binding.

### 3.1 Ticker Grammar

The root ticker grammar is:

```
ROOT := [A-Z][A-Z0-9]{2,10}
```

Exactly one child level is permitted:

```
CHILD := ROOT "." SUFFIX
SUFFIX := [A-Z][A-Z0-9]{2,10}
```

Rules:

- no empty root or suffix;
- no lowercase;
- no second dot;
- total ticker length is at most 23 bytes (`11 + 1 + 11`);
- any dotless ticker longer than 11 bytes is invalid;
- dotted tickers can never sponsor children.

The global ticker binding is the full string. `ACME.C150K` and `ACME.P150K` are ordinary
unique ticker keys in the ticker index.

Suffixes use the same 3–11 byte grammar as roots. This forbids compact names such as
`ACME.C1`; that is a deliberate consistency choice, not a parser limit.

The grammar helpers live in `src/assets/asset.cpp`: `IsRootTicker`,
`ParseChildTicker(std::string_view) -> std::optional<ChildTicker>`, and
`IsTickerValidForIssuerReg`. `ParseChildTicker` rejects a second dot and requires both the
root and suffix segments to satisfy `IsRootTicker`.

### 3.2 Child Bond Floor

The child floor is a consensus constant in `src/consensus/params.h`:

```
Consensus::Params::SponsoredChildMinIcuBond = 10'000 sats
```

An initial IssuerReg with a child ticker satisfies the initial bond rule with:

```
out.nValue >= SponsoredChildMinIcuBond
```

instead of:

```
out.nValue >= AssetMinIcuBond
```

only when the parent sponsorship rule below holds. Otherwise the registration is rejected
with `asset-bond-minimum`.

The child then has the normal rotation mechanics:

- `rotation_min_sats = 95% * child_initial_bond`;
- `unlock_fees_sats >= child_current_bond`;
- after the child accumulates its unlock target in touched-asset fees, it may rotate to
  dust like any other ICU asset.

### 3.3 Parent Sponsorship

When binding a child ticker `ROOT.SUFFIX`, the transaction must spend the current ICU UTXO
of the asset bound to root ticker `ROOT`, and that parent ICU prevout must have:

```
prevout.nValue >= AssetMinIcuBond
```

The proof, in `ConnectBlock` asset processing (`src/validation.cpp`):

1. Resolve `ROOT` through the ticker binding index.
2. Read the parent registry entry.
3. Require the parent's current `icu_outpoint` to appear in the transaction inputs; absence
   is rejected with `asset-child-parent-not-spent`.
4. Read the spent parent ICU prevout from the input coin/undo view and require its `nValue`
   to be at least `AssetMinIcuBond`; otherwise reject with `asset-child-parent-underbond`.
5. The ticker string serialized inside the parent ICU input is not trusted. Rotations may
   preserve the registry ticker while omitting it from the new IssuerReg, so the root is
   resolved through the registry/ticker binding, not the input text.

The parent ICU spend requires output-binding signatures under the ICU sighash rule, and
requires exactly one parent successor IssuerReg under the bond-rotation rule. The child
feature adds no parent pointer, child counter, or persistent relationship.

### 3.4 Non-Rules

There is no root-squat restriction. A tickerless asset that posted the full initial bond
may later bind an unclaimed root ticker through the existing rules. It cannot steal an
already-bound ticker, and if it rotates to dust first it has already paid at least the full
bond in sunk fees. That path is not cheaper than naming at birth.

There is no `Sealed()` class. Low-bond children are normal assets. Product-level
trustlessness is proved from the registry fields and confirmed issuance history, not from a
special child class.

The registry holds no parent-child state. Sponsorship is a stateless co-spend proof at the
moment a child ticker is bound.

The parent is not required on ordinary child rotations. The parent authorizes the child
name at birth or later ticker binding. After that, the child is an independent asset.

## 4. Activation

The change is a pure relaxation:

- old blocks cannot contain dotted tickers because the parser rejects them;
- old blocks cannot contain low-bond child registrations because the initial bond rule
  rejects them;
- no previously-valid transaction becomes invalid.

No activation height is required for historical replay safety; the rule is active from
genesis on all networks. There is no BIP9/versionbits gate. All validating and mining nodes
must run a binary that understands dotted tickers before the first dotted-ticker transaction
is mined; nodes that do not will reject that block.

## 5. Implementation

### 5.1 Registry Atomicity Substrate

Asset policy, ticker, VK, and ICU payload mutations are staged through the
`CCoinsViewCache` overlay and committed in the final `CCoinsViewDB::BatchWrite` batch with
`DB_BEST_BLOCK` / `DB_ASSET_BEST_BLOCK`. `ConnectBlock` and `DisconnectBlock` stage registry
mutations into `view`, and registry reads through that view observe prior staged operations
in block order.

The sponsored-child path uses that substrate. The parent sponsorship proof reads the spent
parent ICU prevout value from the same pre-spend input/undo source used by the registry
pass, while parent registry/ticker state is resolved through the active `view` so same-block
staged semantics stay consistent. The consensus path does not read the persistent DB
directly.

### 5.2 Parser and Helpers

The shared ticker helpers live under `src/assets/` rather than as ad-hoc parsing in
validation: `IsRootTicker`, `ParseChildTicker`, `IsTickerValidForIssuerReg`.

`ParseIssuerRegV1` accepts root or one-hop child tickers:

- root length is `3..11`;
- child length is `7..23`;
- ticker bytes are uppercase ASCII letters and digits except for the single dot;
- length `12..23` is valid only when the ticker contains exactly one dot and both sides
  satisfy the root grammar — a 12-byte dotless ticker is rejected.

The parser has no block height context, so parser acceptance does not depend on height. The
height-aware accept/reject rule lives in `validation.cpp`.

### 5.3 Block Consensus

In `ConnectBlock` asset registry processing:

- current ICU inputs are collected with their prevout value retained by input/outpoint so
  the parent sponsorship proof can show a full-bond parent;
- on the ticker-binding path, child tickers are detected and parent sponsorship is enforced;
- on the initial bond check, child initial registrations use `SponsoredChildMinIcuBond` when
  the child ticker sponsorship proof passed;
- reserved-ticker and uniqueness checks are unchanged;
- root ticker behavior is unchanged.

A single transaction may sponsor several children with one parent ICU co-spend. The parent
sponsorship proof is per root, not per child output.

### 5.4 Mempool Policy Mirror

`PreChecks` mirrors the block-consensus accept paths:

- child ticker grammar;
- child initial bond floor;
- parent root lookup;
- parent current ICU input is present (`asset-child-parent-not-spent`);
- parent prevout value is at least `AssetMinIcuBond` (`asset-child-parent-underbond`);
- duplicate ticker checks against confirmed state, mempool state, and in-package state.

The pre-unlock rotation mirror compares the successor bond against `cur.rotation_min_sats`
when one is set, falling back to the previous ICU `nValue` otherwise
(`cur.rotation_min_sats ? cur.rotation_min_sats : prev_bond`). This matches block
validation, so a valid child rotation from 10,000 sats to 9,500 sats is accepted by the
mempool as well as mined.

### 5.5 Undo and Reorg

No new undo state is required. Child tickers use the existing ticker binding index and the
existing asset registry undo. On disconnect, the child ticker binding is erased and the
parent registry entry is restored; reconnect restores both.

## 6. RPC Surface

### 6.1 `sponsorchildasset`

Wallet RPC. Builds and optionally funds/signs a parent-sponsored child registration
(`src/wallet/rpc/assets.cpp`). It is a raw-hex/broadcast RPC matching `registerasset` /
`rotateicu_raw`, not a PSBT RPC, and registers exactly one child per call. The consensus
rule permits several children under one parent co-spend, but that batch path is not exposed
here.

Inputs:

- `root` — the sponsoring root, as ticker or 32-byte `asset_id` hex;
- `suffix` — the child suffix (root grammar); the full child ticker is `ROOT.SUFFIX`;
- `child_asset_id` — 32-byte child asset id hex;
- `child_destination` — the child ICU script/address;
- `options` — an object carrying the child registry fields (`child_bond_sats`,
  `policy_bits`, `allowed_spk_families`, `decimals`, `unlock_fees_sats`,
  `issuance_cap_units`, `policy_quorum_bps`, ICU metadata and payload fields,
  `parent_icu_outpoint` override, `parent_successor_destination`, `autofund`, `broadcast`,
  `fee_rate`, `replaceable`).

`child_bond_sats` defaults to `SponsoredChildMinIcuBond` read from consensus.
`allowed_spk_families` defaults to `28` (P2WPKH | P2WSH | P2TR). `autofund` defaults true;
`broadcast` defaults false.

Behavior:

1. Resolve the parent root and its current parent ICU. A `parent_icu_outpoint` override is
   rejected if its asset differs from the root or it is not the registry's current ICU.
2. Add the parent ICU input.
3. Recreate the parent as a byte-identical successor (reusing the spent ICU's IssuerReg
   bytes) unless an explicit `parent_successor_destination` is supplied.
4. Add the child IssuerReg output with ticker `ROOT.SUFFIX`.
5. Enforce client-side that the child bond is at least `SponsoredChildMinIcuBond`.
6. Fund native fees and change from native UTXOs only (`m_avoid_asset_utxos`); the
   pre-added parent ICU input bypasses that filter, so it never pulls the parent's token
   units or another ICU.
7. With `broadcast=true`, sign and broadcast, surfacing mempool rejection synchronously;
   otherwise return funded raw hex for the caller to sign. If the parent ICU is not
   wallet-spendable, `requires_parent_signature=true` and the hex still needs the parent
   owner's signature.

Output fields include `hex` (and `txid` when broadcast), `child_ticker`, `child_asset_id`,
`child_bond_sats`, `parent_asset_id`, `parent_icu_outpoint`, `parent_successor_vout`,
`child_icu_vout`, `requires_parent_signature`, and `warnings`.

### 6.2 `registerasset`

`registerasset` remains the standalone, root-only full-bond path. Its client-side ticker
grammar check is root-only by design; child creation flows through `sponsorchildasset`,
which also owns the parent-successor rotation ceremony.

### 6.3 Option Series Layer

The option product layer is built on this mechanism: `optionseries.build_register` registers
the option series shell as a sponsored child under an existing root, calling the same
parent-co-spend builder as `sponsorchildasset` and adding option-specific client-side checks
(`MINT_ALLOWED`, explicit `decimals == 0`, `issuance_cap_units == N`, zero governance quorum,
no burn policy, a P2TR-allowed family, and a descriptor payload commitment).

`optionseries.derive` and `optionseries.verify` are read-only core RPCs: `derive` computes a
series `asset_id` and descriptor from terms, and `verify` checks a published series against
its on-chain ICU metadata (including a backing-lot check) so a buyer can confirm the series
is registered and backed before treating it as listable. `optionseries.build_issue`,
`optionseries.record_issue`, `optionseries.list`, and `optionseries.build_settlement` cover
issuance, wallet persistence, and settlement. These are documented in
`OPTION_TOKENIZATION.md`; the child mechanism here only provides the namespaced low-bond
shell they register into.

## 7. Qt Surface

The asset registration UI in `src/qt/treasurypage.cpp` carries the sponsored-child flow
rather than a separate child-asset wizard.

### 7.1 Asset Registration

A registration-mode control selects between:

- `Standalone root` — the full-bond `registerasset` flow;
- `Sponsored child` — low-bond registration under a wallet-controlled parent via
  `sponsorchildasset`.

When `Sponsored child` is selected, a parent dropdown is populated only with
wallet-controlled root assets whose current ICU is known, spendable, and has
`nValue >= AssetMinIcuBond` (dotted children are excluded). After parent selection the rest
of the form mirrors the standalone form, with constrained fields:

- ticker entry becomes a suffix field;
- the full ticker preview is inherited as `PARENT.SUFFIX`; the root part is not editable;
- the child bond defaults to the consensus child floor and cannot be set below
  `SponsoredChildMinIcuBond`;
- all normal registry fields remain available as in the standalone flow.

The review screen shows that the parent ICU is spent and recreated as a successor in the
same transaction, otherwise mirroring the standard registration review.

### 7.2 Option Series

The option-series registration and verification surface reuses the same sponsored
registration control and the same wallet-controlled-roots parent dropdown. It registers the
series shell as a sponsored child (via `optionseries.build_register`), and the verify tab
takes a series ticker (`ROOT.SUFFIX`) or asset id and runs `optionseries.verify` with a
backing check so a buyer can confirm the series is registered, fully issued, and backed
before buying. The option layer itself is documented in `OPTION_TOKENIZATION.md`.

## 8. Test Coverage

`test/functional/feature_icu_child.py` covers the consensus and mempool cases:

- register a full-bond root `ACME`, then a child `ACME.C150K` with a parent ICU co-spend and
  a 10,000-sat child bond;
- register two siblings in one transaction under one parent co-spend;
- reject a child with no parent ICU input (`asset-child-parent-not-spent`);
- reject a child where `ROOT` is not bound;
- reject a child where the parent ICU input is not the current ICU;
- reject a child where the parent's current ICU value is below `AssetMinIcuBond`
  (`asset-child-parent-underbond`);
- reject dotted parent sponsorship (`ACME.C150K.X`);
- reject a wrong-root co-spend (child `ACME.X` while spending `BETA`'s ICU);
- reject reserved-root sponsorship such as `TSC.FOO`;
- reject malformed child tickers (lowercase, empty suffix, short suffix, second dot);
- reject a 12-byte dotless ticker;
- reject a duplicate child ticker;
- accept an ordinary child rotation without parent co-spend;
- accept a pre-unlock child rotation down to `rotation_min_sats` and confirm the mempool
  accepts it;
- accept a post-unlock child rotation to dust after sufficient touched-asset fees;
- mint a child under normal `MINT_ALLOWED` and cap rules, and reject cap overflow with
  `asset-cap-exceeded`;
- disconnect a block that registers a child ticker and confirm reconnect restores it.

RPC and Qt-supporting cases cover `sponsorchildasset` returning funded raw hex with the
parent input, parent successor, and child ICU (and broadcasting/registering when
`broadcast=true`); a non-wallet-spendable parent setting `requires_parent_signature`; the
returned hex broadcasting and registering once signed; and the option-series layer building
the same child registration through the shared builder.

Unit tests in `src/test/asset_tests.cpp` and `src/test/mempool_asset_tests.cpp` cover root
and child ticker grammar, parser acceptance of `ROOT.SUFFIX` and rejection of deeper or
over-length dotless names, resolution of the sponsorship root through the registry rather
than input ticker text, the low-bond-with-valid-parent acceptance, unchanged root behavior,
and the mempool rotation mirror using `rotation_min_sats`.

## 9. Child Bond Constant

The child floor is:

```
SponsoredChildMinIcuBond = 10'000 sats
```

It is intentionally above dust: it gives child registrations a small anti-spam cost while
remaining far below the full root bond.
