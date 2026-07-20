# CFD Generalisation — Issuer-Published Scalar Settlement with Native or Asset Collateral

TensorCash ships a margined, cash-settled covenant opcode, `OP_DIFFCFD_SETTLE` (`0xbe`), that
settles on a single chain-intrinsic scalar (`nBits @ fixing_height`) with native-TSC collateral.
`OP_SCALAR_CFD_SETTLE` (`0xb9`) generalises that covenant along two orthogonal axes:

1. **Generic published scalar.** Settlement reads a scalar that an asset issuer *publishes
   on-chain* (a price / index / intensity feed), resolved by consensus as an **O(1), buried,
   immutable** lookup — never parsed from ICU text, never scanned out of `rotation_history`.
2. **Non-native collateral.** The Initial Margin (IM) posted in the vault, and the settlement
   outputs, may be a **non-TSC asset** (`asset_id = C`), not just native sats. Native TSC is a
   first-class branch selected by a sentinel.

The two compose. The relevant assets the design keeps strictly independent:

| Symbol | Role | Notes |
|---|---|---|
| **U** | the **underlying** — the asset whose issuer publishes the settlement scalar | trusted-issuer oracle (accepted trust model) |
| **C** | the **collateral / IM** asset locked in the vault and paid out at settlement | must be a *simple-transfer*, collateral-safe asset (§5.1) |

`OP_SCALAR_CFD_SETTLE` is a **new, parallel** opcode that shares the payout math and the
resolver-snapshot pattern of `OP_DIFFCFD_SETTLE` — not a mutation of `0xbe`. The chain-intrinsic
difficulty covenant stays exactly as-is as the special case.

All consensus enforcement is gated behind a script-verification flag tied to the
`Consensus::Params::ScalarCfdHeight` activation height (`src/consensus/params.h:196`, default
`INT_MAX`). Below that height `0xb9` is an inert NOP, so the opcode is inactive on networks that
have not set an activation height.

---

## 1. Architecture at a glance

```
                    issuer of U spends U's current ICU (authenticates)  ──────────┐
                    + a SEPARATE carrier output with an ISSUER_SCALAR TLV          │  publication tx
                    {underlying_asset_id, feed_id, scalar_epoch, scalar_format_id, scalar}
                                          │ ConnectBlock parses ONCE               │
                                          ▼                                        │
   dedicated consensus index  DB_ASSET_SCALAR : (U, feed_id, scalar_epoch) ──► {scalar, pub_height, scalar_format_id}
                    (committed atomically with DB_BEST_BLOCK; head record DB_ASSET_SCALAR_HEAD)
                                          │
                                          │ buried >= MATURITY, immutable
                                          ▼
   CheckInputScripts (single-threaded)  pre-scans each scalar-settle input's leaf,
                    extracts the committed (U, feed_id, fixing_ref, deadline, fallback), resolves
                    the scalar from the registry view, applies burial + the deadline/fallback rule →
                    builds an IMMUTABLE scalar-fixing snapshot
                                          │ const-ref, read-only on worker threads
                                          ▼
   OP_SCALAR_CFD_SETTLE (OP_NOP10 = 0xb9, flag-gated by SCRIPT_VERIFY_SCALAR_CFD)
                    folds scalar from the snapshot (never the stack), computes payout,
                    binds the spent input (native nValue OR AssetTag(C, vault_im)),
                    binds asset-tagged or native payout outputs to the two leg keys
```

---

## 2. The opcode: `OP_SCALAR_CFD_SETTLE`

### 2.1 Opcode slot and activation

`OP_SCALAR_CFD_SETTLE` aliases `OP_NOP10` (`0xb9`, `src/script/script.h:208,214`). `0xb9` is the
last clean NOP slot (`0xb7`/`0xb8` are `OP_OUTPUTMATCH_*`); aliasing it keeps it printing as
`OP_NOP10`, leaves `MAX_OPCODE` at `OP_DIFFCFD_SETTLE` (`script.h:232`), and keeps the opcode out of
the OP_SUCCESS sweep — `IsOpSuccess` is untouched. This is the CLTV/CSV upgrade pattern
(`OP_NOP2→0xb1`, `OP_NOP3→0xb2`).

Activation is a **script-verification flag, not an interpreter height check.** `EvalScript` sees
only `flags` and the `checker` context, with no block height — exactly why CLTV/CSV are
flag-driven. `SCRIPT_VERIFY_SCALAR_CFD = 1U << 22` (`src/script/interpreter.h:163`) is set in
`GetBlockScriptFlags` (beside `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY`/`…CSV`) for blocks at or above
`ScalarCfdHeight`. The opcode body gates on `flags & SCRIPT_VERIFY_SCALAR_CFD`: unset → behave as
the legacy NOP10 no-op; set → full covenant enforcement. No height is read inside `EvalScript`.

For mempool relay the flag is computed dynamically from **tip+1** (`GetBlockScriptFlags` for a
block at `tip->nHeight+1`), so relay enforces the covenant one block before the consensus flag-day,
and `PolicyScriptChecks`/`ConsensusScriptChecks` agree across the activation boundary. Pre-activation,
NOP10 is non-standard under `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS`, so scalar leaves do not relay
until active.

**Pre-activation spendability is anchored by tapscript cleanstack.** While the flag is unset,
`0xb9` is an inert no-op, and a canonical scalar-settle vault is **consensus-unspendable, not
stealable**: the §2.2 leaf pushes 16 committed operands and the inert NOP consumes none, so after
execution the tapscript stack holds 16 elements and BIP342's unconditional single-element
("cleanstack") rule rejects the spend. With a NUMS internal key (no key path) and the settle leaf as
the only committed script, the vault cannot be spent at all until the flag activates. As
belt-and-suspenders (not load-bearing for the canonical leaf), wallets may also commit
`<settle_lock_height> OP_CHECKLOCKTIMEVERIFY` at or above `ScalarCfdHeight` so any non-canonical or
multi-leaf vault is also time-fenced past activation.

Scalar resolution is **folded** into SETTLE (like the difficulty leaf, which folds `nBits` and does
not use a separate read primitive). One NOP slot suffices.

### 2.2 Leaf script (committed literals)

```
<contract_id32> OP_DROP                         # per-instance uniqueness (NUMS-shared vaults)
<template_version=0x01>                          # 1 byte: leaf-template version — FIRST committed field after id
<settle_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
<source_type>                                    # 1 byte: 0x00 ISSUER_PUBLISHED / 0x01 CHAIN_INTRINSIC
<underlying_asset_id32>                          # U — whose feed settles this (zero if CHAIN_INTRINSIC)
<feed_id_le4>                                    # ISSUER_PUBLISHED: which feed of U; CHAIN_INTRINSIC: metric_id||window_code
<fixing_ref_le8>                                 # ISSUER_PUBLISHED=scalar_epoch; CHAIN_INTRINSIC=window-end height
<publication_deadline_height_le4>                # last height a real fixing counts; after +grace → fallback (§3.4)
<payoff_mode>                                    # 1 byte: §4 payoff-mode selector (0 STRIKE / 1 REALIZED)
<scalar_format_id_le2>                           # scalar ENCODING; settlement requires published.scalar_format_id == this
<strike_le32>                                    # K, in scalar_format_id's encoding (canonical, round-tripped)
<fallback_scalar_le32>                           # used iff no real fixing by the deadline (§3.4); same encoding
<lambda_q_le4>                                   # Q16 leverage (reused from difficulty)
<loss_direction>                                 # 0x00 long / 0x01 short
<collateral_asset_id32>                          # C — IM/payout asset; 32 zero bytes = NATIVE_SENTINEL (TSC)
<vault_im_le8>                                   # IM in C's units
<owner_key32> <cp_key32>
OP_SCALAR_CFD_SETTLE
```

All economic parameters are committed literals → in the tapleaf hash and the vault address →
tamper-proof. The witness reveals only the leaf + control block: no economic args, no signature
(keeper-settlable). `scalar` is **never** on the stack; it is folded from the snapshot (§3.4). All
numeric operands are fixed-width LE blobs (never `CScriptNum`), exact-length checked.

`template_version` is the first committed field (`SCALAR_CFD_TEMPLATE_VERSION_V1 = 0x01`,
`src/consensus/scalar_cfd_leaf.h:29`). The pre-scan and interpreter dispatch the parse by version;
an unknown version yields no canonical template → fail-closed (§3.4). v1 commits the 16 operands
above.

**Source-specific field meanings:**
- `fixing_ref` (8 bytes) — `ISSUER_PUBLISHED`: the `scalar_epoch` (§3); `CHAIN_INTRINSIC`: the
  window-end **height** the metric is evaluated at.
- `feed_id` (4 bytes) — `ISSUER_PUBLISHED`: which feed of `U`; `CHAIN_INTRINSIC`:
  `metric_id (high 2 bytes) || window_code (low 2 bytes)`. `underlying_asset_id` is zero for
  `CHAIN_INTRINSIC`.

**Canonical push encoding (consensus, exact-template).** Each operand has exactly one legal push
form, required byte-for-byte by both the pre-scan and the interpreter
(`src/consensus/scalar_cfd_leaf.cpp`):
- 4/8/32-byte blobs (`feed_id`, `fixing_ref`, `publication_deadline_height`, `strike`,
  `fallback_scalar`, `lambda_q`, `vault_im`, asset ids, keys): a direct data push of exactly that
  length (`OP_PUSHBYTES_n`), never `OP_PUSHDATA*`, never a `CScriptNum`/`OP_n` shortcut.
- `template_version`/`source_type`/`payoff_mode` (1 byte each), `scalar_format_id` (2 bytes): direct
  data pushes.
- `loss_direction` (1 byte): a raw 1-byte data push of `0x00` (long) or `0x01` (short) — not
  `OP_1`/`OP_TRUE` (which is the opcode `0x51`, a different leaf byte and tapleaf hash).
- `<contract_id> OP_DROP` and `<settle_lock_height> OP_CLTV OP_DROP` use direct pushes.

Any deviation → the pre-scan finds no canonical template → no snapshot entry → the opcode fails
(`SCALARCFD_FIXING`).

### 2.3 Evaluation

The opcode body (`src/script/interpreter.cpp`, the `OP_SCALAR_CFD_SETTLE` case) generalises
`OP_DIFFCFD_SETTLE`:

```
0. CONTEXT GUARD
   if !(flags & SCRIPT_VERIFY_SCALAR_CFD): return success    # legacy NOP10 no-op (pre-activation)
   FAIL unless sigversion == TAPSCRIPT && witness version == 1               (SCALARCFD_CONTEXT)
   FAIL unless the 16 operands parse with exact lengths/encodings            (SCALARCFD_ENCODING)

1. RESOLVE effective scalar (folded, immutable)
   X = snapshot.Get(...)                          # ScalarFixingSnapshot (§3.4)
   FAIL if !X                                                                (SCALARCFD_FIXING)
   # the snapshot has ALREADY applied burial, immutability, and the deadline/fallback rule, and only
   # returns a value whose scalar_format_id == the leaf's. A leaf the pre-scan could not parse to the
   # canonical template yields no entry -> this fails -> parser/interpreter disagreement can never validate.

2. DECODE + CANONICALITY (scalar_format_id-driven, §4)
   (K, X) = DecodeScalar(scalar_format_id, strike, X.scalar)
   FAIL unless ReEncode(scalar_format_id, K) == strike     # canonicality on the STRIKE only

3. PAYOUT  (ComputeScalarCfdPayout — denominator selected by payoff_mode, §4)
   {payout_owner, payout_cp} = formula(payoff_mode, K, X, lambda_q, vault_im, loss_dir)
   FAIL if lambda_q == 0 or vault_im < MIN_SETTLE_OUTPUT                     (SCALARCFD_TERMS)

4. COLLATERAL GATE (native sentinel passes through; asset checked via snapshot — §5.1)
   if collateral_asset_id != NATIVE_SENTINEL:
       pol = snapshot.GetCollateralPolicy(collateral_asset_id)              # resolved single-threaded
       FAIL unless pol && CollateralPolicyGatePasses(pol)                   (SCALARCFD_COLLATERAL)

5. INPUT BINDING
   NATIVE_SENTINEL: FAIL unless checker.GetInputAmount() == vault_im        (SCALARCFD_AMOUNT)
   asset:           in = checker.GetInputAsset()
                    FAIL unless in && in.asset_id==C && in.asset_amount==vault_im  (SCALARCFD_AMOUNT)

6. OUTPUT BINDING (VerifyScalarCfdOutputs — EXACT-distinct)
   for each non-zero leg → require a DISTINCT output with scriptPubKey == OP_1<leg_key> (exact) and:
     NATIVE_SENTINEL: nValue == payout_leg (exact, no AssetTLV)
     asset:           AssetID()==C && AssetAmount()==payout_leg (exact),
                      nValue >= SCALARCFD_ASSET_OUTPUT_DUST (NOT exact — keeper funds the dust)
   one output may not satisfy two legs.   (else SCALARCFD_OUTPUTS / SCALARCFD_CONTEXT)

7. pop the 16 operands, push true (VERIFY-style)
```

**Native collateral is a first-class branch.** `collateral_asset_id == NATIVE_SENTINEL` (32 zero
bytes) selects native-TSC binding (input `GetInputAmount`, output exact `nValue`, no AssetTLV) —
byte-for-byte the difficulty semantics.

Differences from difficulty, each load-bearing:
- **Input binding** for the asset branch compares `AssetTag(C, vault_im)` not native `nValue`, via a
  `BaseSignatureChecker::GetInputAsset()` virtual returning the spent coin's `{asset_id, asset_amount}`
  (or nullopt for a native/contextless coin, which makes an asset contract over a native input fail).
- **Output binding** matches asset-tagged outputs with exact asset_id + exact asset amount + exact
  spk, but `nValue >= SCALARCFD_ASSET_OUTPUT_DUST` rather than `== committed` — the keeper funds the
  native dust carried alongside the asset TLV. `VerifyScalarCfdOutputs`
  (`src/script/interpreter.cpp:2551`) keeps the exact-distinct discipline, asset-aware, and is a
  distinct helper from `OP_OUTPUTMATCH_ASSET`'s existential matcher.

`SCALARCFD_ASSET_OUTPUT_DUST` is set equal to the native `MIN_SETTLE_OUTPUT` floor (546 sats,
`src/consensus/scalar_cfd.h:22`).

---

## 3. The scalar publication subsystem (O(1), ICU-decoupled)

### 3.1 Carrier: a dedicated `ISSUER_SCALAR` output TLV

`CTxOut::vExt` holds exactly one TLV (`ValidateSingleTLV`, enforced at deserialize). The ICU
successor output already carries `ISSUER_REG` (`0x10`), so a scalar cannot share it.
`OutExtType::ISSUER_SCALAR = 0x11` (`src/assets/asset.h:20`) is carried on a **separate carrier
output** in the same publication tx. The carrier should use a provably-unspendable scriptPubKey so
it does not bloat the UTXO set — the *state* lives in the index (§3.2); the output is a one-time
carrier consumed at ConnectBlock.

The fixed-width TLV body is 78 bytes (`ISSUER_SCALAR_BODY_SIZE`, `src/assets/asset.h:366`), with no
JSON and no nesting:

```
underlying_asset_id : 32 bytes   # EXPLICIT — must equal an ICU asset spent by this tx (disambiguation)
feed_id             : uint32
scalar_epoch        : uint64     # monotonic per (asset_id, feed_id); independent of policy_epoch
scalar_format_id    : uint16     # scalar ENCODING only (§4). A publication is mode-agnostic; the
                                 #   payoff-mode selector lives in the SETTLEMENT LEAF, not here.
scalar              : 32 bytes   # raw 256-bit value interpreted per scalar_format_id. Stored at a
                                 #   FIXED 32-byte width — the index is format-agnostic; decoding is
                                 #   the interpreter's job (§4).
```

The parser (`ParseIssuerScalar`) is purely structural — it validates the 78-byte shape and performs
no semantic checks; authentication lives in the ConnectBlock publication rule (§3.3).

**Carrier disambiguation.** Because a tx may co-spend several ICUs, the TLV carries the
`underlying_asset_id` explicitly, and ConnectBlock requires it to match the asset of a current-ICU
input actually spent (and thus authenticated) by this tx.

**Same-asset publication is one per block under standard relay.** A scalar publication spends and
recreates the asset's ICU, emitting an `ISSUER_REG` successor, and ConnectBlock enforces at most one
`ISSUER_REG` per asset per block (`asset-rotation-limit`). Different assets may each publish once per
block. Same-asset multiple epochs in one block is only possible as a single tx with one ICU successor
plus multiple `ISSUER_SCALAR` carriers (deterministic vout order, each `epoch == head+1`); since a
carrier must be provably unspendable (`OP_RETURN`) and standard relay rejects more than one
`OP_RETURN` per tx, that multi-carrier tx is block-valid but not relay-standard. `scalarpublish_raw`
emits exactly one carrier per tx. Block tx order then vout order is the deterministic publication
order in all cases.

### 3.2 State: a dedicated index, atomic with best-block

- **LevelDB namespaces** `DB_ASSET_SCALAR = 'S'` and `DB_ASSET_SCALAR_HEAD = 's'`
  (`src/txdb.cpp:35-36`).
- **Per-epoch key** = fixed-width `(asset_id:32, feed_id:4, scalar_epoch:8)` → a single point lookup
  (O(1), same cost class as a coin read). **Value** = `{ scalar, publication_height:int32,
  scalar_format_id:uint16 }`. No history scan, no large-blob deserialize.
- **Head record** = `(asset_id, feed_id) → last_epoch:uint64`, required so the monotonicity check
  (`epoch == last+1`) and "latest epoch" lookups are O(1). Both records are staged/undone together.
- **Atomicity**: per-epoch entries and head records are staged in `CAssetRegistryDelta` alongside
  `policy/ticker/vk/icu`, and committed in the same `CDBBatch` as `DB_BEST_BLOCK` /
  `DB_ASSET_BEST_BLOCK`. Undo via a `scalar_undo` channel in `CBlockUndo` that restores both the
  erased epoch entry and the prior head. Reorg-safe by construction.

`rotation_history` (capped `MAX_ROTATION_HISTORY=100`, nested in the large `AssetRegistryEntry` blob)
and the ICU payload namespace `'I'` are explicitly **not** used. The scalar feed is a separate
concern.

### 3.3 Publication validation (ConnectBlock, single pass)

A tx is a valid scalar publication iff:
1. It **spends U's current ICU** (`AssetRegistryEntry::icu_outpoint`) → issuer-authenticated.
2. It has **exactly one** `ISSUER_SCALAR` carrier output for `(U, feed_id)`.
3. `scalar_epoch == head(U, feed_id).last_epoch + 1` (0 if none) — **monotonic, append-only**.
4. `(U, feed_id, scalar_epoch)` **does not already exist** — **immutable, never overwritten**.
5. `scalar_format_id` is known and `scalar` is canonical for it.

**Allowlist gating.** ConnectBlock carries an output-TLV allowlist that rejects any `vExt` not
parsed as a known type (`"unknown vExt TLV in output"`). `ISSUER_SCALAR` (`0x11`) is added to that
allowlist **height-gated behind `ScalarCfdHeight`** and atomically with the publication validation:
below the height, `0x11` is rejected exactly as before, so pre-activation blocks validate
identically; the codec/parser alone never makes unauthenticated carriers valid.

The index entry is written with `publication_height = this block height`. A published scalar's value
is fixed forever; only its *burial status* evolves. The per-feed epoch counter is the `uint64` head
record, independent of `policy_epoch` (which is `uint8_t`).

### 3.4 Resolution: immutable snapshot, never a live cache read on worker threads

`CScriptCheck` runs on `CCheckQueue` worker threads in parallel; they must not read mutable
`CoinsTip`/`CCoinsViewCache`. The difficulty path is safe only because it reads immutable block-index
ancestry. For scalars this immutability is replicated:

- In `CheckInputScripts` (`src/validation.cpp`), **single-threaded, before queue dispatch**, the
  witness pre-scan `ScanScalarCfdWitness` (`validation.cpp:309`) detects `OP_SCALAR_CFD_SETTLE`
  leaves and reads the committed `(source_type, U, feed_id, fixing_ref, publication_deadline_height,
  fallback_scalar)` pushes from each revealed leaf.
- Each needed scalar is resolved from the registry view (safe here), with burial + the
  deadline/fallback rule applied against the connecting block height, and frozen into an immutable
  scalar-fixing snapshot (`src/consensus/scalar_cfd_snapshot.{h,cpp}`).
- The snapshot is passed by `const&` into every `CScriptCheck`. The opcode's resolver reads only the
  frozen snapshot.

**Fail-closed pre-scan.** Detection of "this leaf contains `OP_SCALAR_CFD_SETTLE`" is conservative
(shares the difficulty pre-scan's `GetOp`-based witness extraction, agreeing byte-for-byte on "the
revealed leaf"). On any detection it sets the non-cacheable flag (§3.5) and counts toward the
one-settle-input rule (§3.6) — over-counting is always safe. **Operand extraction is exact**: if the
revealed leaf does not match the canonical template, the pre-scan provides no snapshot entry, the
opcode hits `snapshot.Get → nullopt`, and fails (`SCALARCFD_FIXING`). Detection over-approximates;
resolution under-approximates; both fail safe.

**Burial** uses the same predicate shape as difficulty: `pub_height <= context_height - MATURITY` and
`pub_height < context_height`. Same-block publication is never usable → no intra-block dependency
races. A buried publication lives in the committed base view, so the read is stable during this
block's connection.

**Deadline / missing-fixing fallback (folded into resolution, not a racing leaf).** A note must
never lock collateral forever if the issuer never publishes. The leaf commits
`publication_deadline_height` and `fallback_scalar`, and `ResolveScalarFixing`
(`src/consensus/scalar_cfd.cpp`) applies a deterministic three-way rule:

```
real = published (U, feed_id, fixing_ref)
usable_real = real exists
           AND real.scalar_format_id == leaf.scalar_format_id      # wrong encoding -> unusable
           AND real.pub_height <= publication_deadline_height       # late publication -> unusable
           AND buried(real.pub_height)
if usable_real:
    effective = real.scalar
elif context_height >= publication_deadline_height + max(SCALARCFD_FALLBACK_GRACE, MATURITY):
    effective = fallback_scalar
else:
    effective = nullopt                     # still pending → opcode fails, wait
```

- **Late publications are ignored** (`pub_height > publication_deadline_height` does not count), so
  once past the deadline the fixing is fixed — there is no keeper/bribery race between a late "real"
  publication and a "fallback" spend. This is why it is a resolution rule, not a second leaf.
- **Format mismatch is an unusable real fixing, not a hard fail:** a record whose `scalar_format_id`
  differs from the leaf's is ignored like a late/missing fixing, so the contract falls through to the
  committed fallback. The resolved `effective` is therefore always in the leaf's `scalar_format_id`,
  so the opcode needs no separate format-equality check.
- `ResolveScalarFixing` enforces `max(grace, MATURITY)` as the effective grace, so a fixing published
  at or before the deadline is always buried (wins branch 1) before the fallback can fire — even if a
  chainparam mis-sets grace < maturity. No race by construction.
- **Overflow safety:** `publication_deadline_height` is a leaf-committed `uint32`; all height
  arithmetic is done in `int64_t`, so an adversarial near-`INT_MAX` deadline cannot signed-overflow
  consensus code.
- `fallback_scalar` is in the same `scalar_format_id` encoding as `scalar`/`strike`; the opcode
  computes the payout from `effective` exactly as for a real fixing.

`source_type = CHAIN_INTRINSIC` is template-valid in the leaf parser but is not resolved by the v1
snapshot: it reads an objective chain metric rather than the `DB_ASSET_SCALAR` index, so the snapshot
adds no entry for such a leaf and the opcode fails closed (`SCALARCFD_FIXING`). Only
`ISSUER_PUBLISHED` settles.

### 3.5 Non-cacheability

A settlement tx reading a published scalar bypasses the script-validity cache, exactly as difficulty
does. Even though an epoch's value is immutable while it exists, a deep reorg (> MATURITY) can remove
or replace the publication on the new chain, so the same wtxid can validate differently. The pre-scan
sets `reads_resolved_scalar` when an `OP_SCALAR_CFD_SETTLE` leaf is revealed, which (together with the
difficulty flag) bypasses the cache (`validation.cpp:3329`).

### 3.6 One-settle-input rule

The fund-safety rule "≤1 input per tx revealing a settle covenant" exists because the per-evaluation
`consumed` set only protects a single opcode run. It is shared across both opcodes: the pre-scan
counts difficulty and scalar settle leaves together, and a tx with `diffcfd_settle_inputs +
scalarcfd_settle_inputs > 1` is rejected (`validation.cpp:3326`). Settlement is always one leg per tx.

---

## 4. Economic model — payoff modes

`scalar_format_id` and `payoff_mode` are **two separate operands**: `scalar_format_id` selects the
**encoding** (how the 32-byte scalar/strike/fallback are read — published in the `ISSUER_SCALAR`
record and re-committed in the leaf, which must match), and `payoff_mode` selects the
**denominator/convexity** (committed in the leaf only — a publication is mode-agnostic). Keeping them
distinct lets one published feed back contracts with different payoff modes.

`ComputeScalarCfdPayout` (`src/consensus/scalar_cfd.cpp`) generalises the difficulty
`ComputeDiffCfdPayout`: clamped `f_loss`, single floor (remainder to owner), sub-dust leg snapped,
512-bit accumulator envelope. The denominator is selected by `payoff_mode`:

| mode | denominator | `f_loss` | meaning | when |
|---|---|---|---|---|
| **0 STRIKE** | committed `K` | `clamp(λ·\|X−K\|/K, 0, 1)` = `clamp(λ·\|X/K−1\|, 0, 1)` | percent move from strike, symmetric, linear in X, deterministic (K committed) | generic price/index feeds |
| **1 REALIZED** | resolved `X` | `clamp(λ·\|X−K\|/X, 0, 1)` | reproduces difficulty semantics (linear in 1/X) | rate/intensity feeds where the ratio is the natural variable |

The interpreter maps `payoff_mode == 0x01 → ScalarLossDenominator::REALIZED`, otherwise
`ScalarLossDenominator::STRIKE` (`interpreter.cpp:1469`). Mode 0 is overflow-safe (K is a committed
bound); mode 1 needs no extra operand (the denominator is the resolved `X`).

**Encoding.** The v1 scalar format is `SCALAR_FORMAT_RAW_U256_LE = 0x0001` (`src/assets/asset.h:377`),
a raw fixed 32-byte little-endian 256-bit value; `IsKnownScalarFormat` accepts it. The 512-bit
math envelope covers all products. Canonicality round-trips the **strike** only; the realized scalar
is consensus-read.

---

## 5. Non-native collateral (asset C)

- **Resolver surface** `GetInputAsset()` on `BaseSignatureChecker` returns the spent coin's
  `{asset_id, asset_amount}` (`CovenantInputAsset`) or nullopt. It is plumbed through `CScriptCheck`
  from the connecting view, single-threaded (`validation.cpp:3202-3206`), like the fixing context.
- **Output binding** as in §2.3 step 6: exact `(asset_id, amount, spk)`, `nValue >=
  SCALARCFD_ASSET_OUTPUT_DUST`.
- **Asset conservation:** a settlement spends one `AssetTag(C, vault_im)` vault and emits ≤2
  `AssetTag(C, ·)` outputs summing to `vault_im` → asset delta `d == 0` → pure transfer, no ICU
  required (`tx_verify.cpp`). The native fee comes from a separate input; the IM split is never
  shaved.
- **Asset dust:** the per-leg floor is `SCALARCFD_ASSET_OUTPUT_DUST` (= `MIN_SETTLE_OUTPUT`, 546),
  dust-snapped in `ComputeScalarCfdPayout`.

### 5.1 Collateral compatibility gate — consensus, not wallet-only

`tx_verify.cpp` skips `allowed_spk_families` on `d==0`, but the KYC/wrap/TFR witness pass still
applies. A keyless covenant cannot supply ZK proofs or wrap material, so a collateral asset carrying
those constraints would make settlement invalid → funds trapped. The danger is *drift*: an asset
clean at vault creation could become constrained before a long-dated note settles. Source analysis of
what can vs cannot drift:

- **`kyc_flags`, `tfr_flags`, `policy_bits`, `allowed_spk_families` are hard-immutable after
  issuance** — covered by `core_policy_commit` (`ComputeCorePolicyCommit`, enforced in
  ConnectBlock, "policy-core-changed"). The KYC trigger is `kyc_flags != 0`.
- **`icu_flags` (where `WRAP_REQUIRED` = 0x0001 lives) is governance-mutable and not frozen by
  `quorum_bps == 0`.** It is excluded from `core_policy_commit`; the rotation immutability check
  covers only `icu_commit/icu_visibility/quorum_bps/cap` changes and the `quorum_bps == 0` hard-stop
  lives inside `if (governance_changed)`, so a rotation that changes only `icu_flags` bypasses it. By
  itself, then, `WRAP_REQUIRED` could be turned on at any time by the ICU holder — a settlement-time
  current-policy check would be safe but would not give *liveness* for long-dated notes.

**The collateral-safe profile bit resolves this at consensus.** `COLLATERAL_SAFE = 0x0040`
(`src/assets/asset.h:282`) is an immutable policy bit committed at registration and folded into
`core_policy_commit`. Above `ScalarCfdHeight`, ConnectBlock rejects any rotation of a
`COLLATERAL_SAFE` asset that toggles the bit itself or changes `icu_flags`
(`src/assets/asset.cpp:516-517`; the guard rule in `asset.h:301-304`), and re-affirms the
already-immutable `kyc_flags`/`tfr_flags` — those fields are frozen for the asset's life. Below the
height the bit is an ordinary policy bit with no extra meaning (`validation.cpp:5564`), so the rule is
inactive pre-activation.

The opcode's collateral gate (`SCALARCFD_COLLATERAL`, §2.3 step 4) then requires the collateral asset
to carry `COLLATERAL_SAFE` and have clean `kyc_flags`/`tfr_flags`/`WRAP_REQUIRED`, checked against the
single-threaded snapshot policy via `CollateralPolicyGatePasses`
(`src/consensus/scalar_cfd_snapshot.cpp`). Because the bit guarantees immutability from registration,
the value resolved at settlement always equals creation-time → **safe (no griefing/bypass) and live
(a conforming vault always settles)**. A settlement-time equality check alone would not buy liveness:
if a mutable asset flipped `WRAP_REQUIRED`, the check would just turn "tx_verify rejects" into
"covenant fails" — funds trapped either way. Only registration-time immutability guarantees a
long-dated note can always settle.

`decimals` is not consensus-critical (integer units); it is a wallet sanity check only.

---

## 6. Security properties

- **Trusted-issuer oracle.** For `ISSUER_PUBLISHED` feeds the issuer can publish any value;
  immutability + monotonic epochs bound that freedom to "value-at-publish + timing". A position
  references a *future* epoch and trusts the issuer for it. This is weaker than the objective
  difficulty feed by design.
- **Oracle liveness — missing fixing.** A never-published feed cannot lock collateral forever: the
  committed `publication_deadline_height` + `fallback_scalar` deterministically settle the note after
  `deadline + max(grace, MATURITY)` (late publications ignored, no race; §3.4).
- **Collateral policy drift.** `icu_flags`/`WRAP_REQUIRED` is governance-mutable, but the immutable
  `COLLATERAL_SAFE` bit freezes it (and re-affirms `kyc_flags`/`tfr_flags`) from registration, so a
  conforming vault always settles and cannot be griefed (§5.1).
- **Threading.** All consensus-relevant reads (scalar fixing, collateral policy) are resolved
  single-threaded into an immutable snapshot before queue dispatch; worker threads touch no mutable
  cache (§3.4).
- **Pre-activation safety.** Below `ScalarCfdHeight` the opcode is an inert NOP and a canonical
  scalar vault is consensus-unspendable by the cleanstack rule; the `ISSUER_SCALAR` allowlist entry is
  height-gated, so pre-activation blocks validate identically (§2.1, §3.3).
- **Reorg safety / non-cacheability.** Index writes/undos are atomic with best-block; a deep reorg
  can change a fixing, so scalar-reading txs bypass the script cache (§3.2, §3.5).
- **Fund-safety pre-scan.** The shared one-settle-input rule keeps settlement to one leg per tx, and
  the fail-closed pre-scan ensures a malformed-but-detected leaf can never validate (§3.4, §3.6).
- **Overflow.** Height arithmetic is `int64_t`; payout math uses a 512-bit accumulator envelope.

---

## 7. RPC surface

The publication / feed layer is exposed by three node RPCs (`src/rpc/scalar.cpp`):

- **`scalarpublish_raw`** — builds the publication tx: spends the issuer's current ICU and emits the
  `ISSUER_SCALAR` carrier for `(underlying_asset_id, feed_id, scalar_epoch)`. `scalar_epoch` must
  equal the current head + 1 (or 1 if none).
- **`scalargetfeed`** — reads `(asset_id, feed_id, epoch)` → `{scalar, scalar_format_id,
  publication_height, …}` and burial state.
- **`scalarlistfeeds`** — enumerates an asset's feeds / epochs.

Argument-type conversions for the CLI are registered in `src/rpc/client.cpp:391-400`.

---

## 8. Source map

Consensus / opcode:
- `src/script/script.h` — `OP_SCALAR_CFD_SETTLE = OP_NOP10 = 0xb9`; `MAX_OPCODE`/OP_SUCCESS untouched.
- `src/script/interpreter.h` — `SCRIPT_VERIFY_SCALAR_CFD = 1U<<22`; `GetInputAsset()` +
  `CovenantInputAsset`; the scalar-fixing snapshot accessor.
- `src/script/interpreter.cpp` — the opcode body (native-sentinel + asset branches),
  `VerifyScalarCfdOutputs`.
- `src/script/script_error.{h,cpp}` — `SCALARCFD_{CONTEXT,ENCODING,FIXING,TERMS,COLLATERAL,AMOUNT,OUTPUTS}`.
- `src/consensus/scalar_cfd_leaf.{h,cpp}` — the canonical leaf-template parser
  (`SCALAR_CFD_TEMPLATE_VERSION_V1`, source-type / encoding validation).
- `src/consensus/scalar_cfd.{h,cpp}` — `ComputeScalarCfdPayout` (mode-parameterised denominator),
  `ResolveScalarFixing`, burial predicate, `SCALARCFD_ASSET_OUTPUT_DUST`.
- `src/consensus/scalar_cfd_snapshot.{h,cpp}` — the immutable fixing/collateral snapshot type and
  `CollateralPolicyGatePasses`.
- `src/consensus/params.h` — `ScalarCfdHeight`, maturity / fallback-grace depths.
- `src/validation.cpp` — `GetBlockScriptFlags` height-gate; `PolicyScriptChecks`/`ConsensusScriptChecks`
  tip+1 flags; ConnectBlock publication validation + `COLLATERAL_SAFE` immutability rule;
  `ScanScalarCfdWitness` pre-scan building the snapshot, non-cacheable flag, shared one-settle-input rule.

Scalar publication + index:
- `src/assets/asset.h` — `OutExtType::ISSUER_SCALAR = 0x11`, fixed-width 78-byte TLV,
  `COLLATERAL_SAFE = 0x0040`, `SCALAR_FORMAT_RAW_U256_LE`, `IsKnownScalarFormat`.
- `src/assets/asset.cpp` — `COLLATERAL_SAFE` rotation immutability check.
- `src/txdb.cpp` — `DB_ASSET_SCALAR` / `DB_ASSET_SCALAR_HEAD` read/write/erase + atomic batch.
- `CBlockUndo` — `scalar_undo` channel; disconnect erases the epoch entry and rolls back the head.
- `src/rpc/scalar.cpp`, `src/rpc/client.cpp` — the feed RPCs.

## 9. Tests

- `src/test/scalar_cfd_leaf_tests.cpp` — canonical leaf-template parsing.
- `src/test/scalar_cfd_payout_tests.cpp` — golden payout vectors per mode (sum-to-IM, clamp
  boundary, dust-snap), difficulty-parity vectors.
- `src/test/scalar_cfd_snapshot_tests.cpp` — the §3.4 three-way resolution rule and the collateral
  gate.
- `src/test/scalar_cfd_validation_tests.cpp`, `src/test/scalar_cfd_eval_tests.cpp` — opcode evaluation
  and validation wiring.
- `test/functional/feature_scalar_publication.py` — publication: cross-wallet, activation boundary,
  burn-safety, monotonic/immutable epochs, reorg head-restore.
- `test/functional/feature_scalar_settle.py` — native-collateral settlement: premature reject → bury
  → honest settle + receipts → greedy-keeper reject → activation boundary.
- `test/functional/feature_scalar_settle_asset.py` — non-native (asset) collateral settlement and the
  collateral-safe gate.
