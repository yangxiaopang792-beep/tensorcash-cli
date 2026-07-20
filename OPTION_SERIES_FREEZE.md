# Option Series Descriptor Spec — descriptor bytes, ICU metadata bands, vault leaf set

The byte-level / schema-level contract that defines a tokenized difficulty-option series. Every item
here moves the bytes that `asset_id = H(descriptor)` commits to, so two independent implementations
following this spec derive byte-identical `asset_id`, vault outputs, pots, and sinks for the same
inputs. Companion to `OPTION_TOKENIZATION.md` (the design) and `ICU_CHILD.md` (the sponsored-child
registration substrate).

A series is described by a fixed-layout binary **descriptor**. There are two descriptor versions:

- **`descriptor_version = 1`** — call-only. A 103-byte body (§2). A v1 descriptor is implicitly a
  CALL (writer short).
- **`descriptor_version = 2`** — directional. The v1 103-byte body plus **one trailing `direction`
  byte** (`0x00` = CALL / writer-short, `0x01` = PUT / writer-long) → 104 bytes total.

v1 and v2 share one identity scheme: the asset-id tag is a **fixed domain across versions** (§3), and
a parser gates length against version — 103 bytes ⟺ v1, 104 bytes ⟺ v2; any other pairing is
malformed (`ParseOptionSeriesDescriptor`, `src/wallet/option_series.cpp`). For a put the writer funds
the **long** difficulty leg instead of the short leg; the sink/pot/vault derivations, the settlement
covenant, and redemption are otherwise identical — `ComputeDiffCfdPayout(short_leg = writer_short)`
flips the payout polarity. The buyer-side ICU-metadata verifier accepts both 103- and 104-byte
descriptors.

The reference derivation core lives in `src/wallet/option_series.{h,cpp}`: the binary descriptor (§2),
`asset_id` (§3), and the per-lot salt / sink / pot / vault derivations (§4). Everything there is pure
(no wallet/UTXO state) and deterministic from the descriptor. The lot vault reuses the existing
`BuildDifficultyLeafScript` / `ComputeDifficultyContractId` verbatim (writer = short leg for a call,
long leg for a put) and composes the option-specific buy-back leaf around them; no consensus code is
added by the option-series layer.

---

## 1. Design choices

### D1 — Vault leaf set

A tokenized lot vault is a P2TR with internal key `NUMS_H`. The tap tree is one of:

| Option | Leaves | Effect | Cost |
|---|---|---|---|
| **D1-a** settle-only (`leaf_set = 0`) | `{ settle_leaf }` | no early unwind; holders exit only by selling units | smallest tree/witness; one leaf |
| **D1-b** settle + buy-back (`leaf_set = 1`, default) | `{ settle_leaf, buyback_leaf }` | writer may repurchase units on market and retire one to `sink_i` to reclaim that lot's collateral early (`OPTION_TOKENIZATION.md` §8.4) | +1 leaf; +1 control-block depth |

The coop-close leaf is deliberately excluded either way — its `OP_CHECKSIG` arm is dead weight once
`cp_key` is a covenant key with no signer (`OPTION_TOKENIZATION.md` §2.2). Early unwind is cheap to
include at issuance and impossible to retrofit without minting a new series, so D1-b is the default.
The descriptor records the choice in `leaf_set` (§2) so verifiers re-derive the right tree.
`CreateOptionVaultBuilder` produces the settle-only tree (single depth-0 leaf) when the buy-back leaf
is empty, and the settle + buy-back tree (both leaves at depth 1) otherwise.

### D2 — Encoding split

| Surface | Encoding |
|---|---|
| Descriptor (feeds `H(descriptor)`) | **fixed-layout binary** (§2) |
| Metadata bands (display / index) | **canonical JSON** (§6) — matches the `TSC-ICU-CONTEXT-1` UniValue shape |

The descriptor must reproduce byte-for-byte to recompute `asset_id`; a fixed binary layout guarantees
that (no key-ordering, whitespace, or number-formatting ambiguity). The metadata bands are
non-identity display/index data parsed by renderers, so canonical JSON (§6.1) matches the existing
context-map machinery and is easier to extend.

---

## 2. Descriptor binary layout

Fixed-order, fixed-width, little-endian. No TLV — the `descriptor_version` byte gates the whole
layout, so a new field set = a version bump = a new layout. x-only keys are 32-byte BIP340. The body
is **103 bytes** (v1); v2 appends one trailing `direction` byte → **104 bytes**.
(`SerializeOptionDescriptor` / `ParseOptionSeriesDescriptor`, `src/wallet/option_series.cpp`.)

| Off | Field | Type | Bytes | Notes |
|---|---|---|---|---|
| 0  | `descriptor_version` | u8 | 1 | 1 = call-only (103B); 2 = directional (104B) |
| 1  | `issuance_mode` | u8 | 1 | 0 = self-issuance, 1 = bilateral |
| 2  | `leaf_set` | u8 | 1 | 0 = settle-only, 1 = settle+buyback |
| 3  | `writer_key` | x-only | 32 | issuer/writer **raw signable** key (known DL, NOT covenant/NUMS) — both the writer-leg payout output key AND the buy-back signing key (§4) |
| 35 | `strike_nbits` | u32 LE | 4 | compact target |
| 39 | `fixing_height` | u32 LE | 4 | |
| 43 | `settle_lock_height` | u32 LE | 4 | CLTV |
| 47 | `lambda_q` | u32 LE | 4 | Q16 leverage |
| 51 | `lot_im_sats` | u64 LE | 8 | per-lot IM = K/N (native sats) |
| 59 | `lot_count` (N) | u32 LE | 4 | |
| 63 | `reference_premium_sats` | u64 LE | 8 | display/listing only under self-issuance; the enforced premium output amount under bilateral (`OPTION_TOKENIZATION.md` §6.1). MAY be 0 |
| 71 | `series_salt` | bytes32 | 32 | the only randomness; NOT per-lot salts (those derive — §4) |
| 103 | `direction` | u8 | 1 | **v2 only**: 0 = CALL (writer short), 1 = PUT (writer long) |

Fixed instrument facts (NOT stored — implied by `kind=OPTION` so they can't disagree with the leaf):
`decimals = 0`; the single funded difficulty leg is the writer's leg (short for a call, long for a
put). Per-lot `cp_key`, salts, pot/sink keys are all **derived** (§4), never stored — storing them
would be circular (`OPTION_TOKENIZATION.md` §2.1).

`descriptor` = the exact bytes above, in order, no padding.

---

## 3. `asset_id` / `series_id` derivation

```
series_id = asset_id = TaggedHash("TSC-OptionSeries/v1", descriptor)
```

A BIP340-style tagged hash (`SHA256(SHA256(tag) || SHA256(tag) || descriptor)`); the tag is the ASCII
string `TSC-OptionSeries/v1` (`OPTION_SERIES_ID_TAG`, `src/wallet/option_series.h`;
`ComputeOptionSeriesId`, `option_series.cpp`). The tag is a **fixed domain across all descriptor
versions** — it is NOT bumped per `descriptor_version`. Collision-freedom comes from the descriptor
itself: its first byte IS `descriptor_version` and the versions differ in length (v1 = 103, v2 = 104),
so the hashed preimages can never coincide. (The `/v1` suffix names the fixed tag scheme, not the
descriptor version.)

This is **convention, not consensus** (`OPTION_TOKENIZATION.md` §9.2 covers the consensus-bound
variant). `asset_id` is the caller-supplied id passed to `registerasset` / `sponsorchildasset`;
verifiers recompute it and reject a mismatch. The on-chain registry display/lookup hex for the same
32 bytes is the reverse-byte form (`OptionSeriesRegistryIdHex` = `uint256::GetHex`): the option-series
canonical id is `HexStr(series_id)` (forward, §7), but `registerasset` / `mintasset` and
`getassetinfo` / `getassetpolicy` / `geticupayload` speak this reverse-hex form. One documented
boundary lets the core (derive/verify) and wallet (build_register/build_issue) RPCs agree, and a
buyer may pass either form to `optionseries.verify`.

---

## 4. Per-lot derivations (exact, for lot index `i` in `0..N-1`)

All `le32(x)` are 4-byte little-endian. Existing helpers are referenced by name; the option-series
layer does not re-implement them. (`DeriveOptionLot` and friends, `src/wallet/option_series.cpp`.)

1. **Lot salt** — `salt_i = TaggedHash("TSC-OptionSeries/lot", series_id || le32(i))`
   (`DeriveOptionLotSalt`).
2. **Sink key** — counter-loop to a valid x-only point (`DeriveOptionSink`):
   ```
   for ctr = 0, 1, 2, …:
       x = TaggedHash("TSC-OptionSeries/sink", series_id || le32(i) || le32(ctr))
       if x lifts to a valid BIP340 x-only point: sink_key_i = x; break
   sink_spk_i = P2TR(sink_key_i) = OP_1 <sink_key_i>          // untweaked; provably unspendable
   ```
3. **Pot** — single-leaf P2TR, internal `NUMS_H` (`BuildOptionPotLeaf` + `CreateOptionPotBuilder`):
   ```
   tapmatch_i = ComputeTapMatch(sink_spk_i)                    // SHA256("TapMatch" || sink_spk_i), src/script/interpreter.h
   pot_leaf_i = <tapmatch_i:32> <asset_id:32> <0x0100000000000000> OP_OUTPUTMATCH_ASSET   // OP_OUTPUTMATCH_ASSET = 0xb8
   pot_key_i  = NUMS_H tweaked by TapTweak(merkleroot({pot_leaf_i}))   // BIP341
   ```
4. **Lot terms & vault** — build the lot's `DifficultyContractTerms` (`kind = OPTION`; the writer's
   funded leg has `owner_key = writer_key`, `cp_key = pot_key_i`, `im = lot_im_sats`, `lambda_q`;
   `premium = MIN_SETTLE_OUTPUT`), then:
   ```
   contract_id_i = ComputeDifficultyContractId(terms_i, salt_i)           // existing
   settle_leaf_i = BuildDifficultyLeafScript(record_i, is_short = writer_short)  // existing, byte-for-byte
   buyback_leaf_i = <writer_key:32> OP_CHECKSIGVERIFY <tapmatch_i:32> <asset_id:32> <0x0100000000000000> OP_OUTPUTMATCH_ASSET   // D1-b only
   // Tap tree (BIP341), leaf version 0xc0 (TAPROOT_LEAF_TAPSCRIPT), internal key NUMS_H:
   //   D1-b: Add(1, settle_leaf_i); Add(1, buyback_leaf_i); Finalize(NUMS_H)
   //   D1-a: Add(0, settle_leaf_i);                          Finalize(NUMS_H)
   vault_key_i = builder output key      // = NUMS_H tweaked by TapTweak(NUMS_H || merkleroot(leaves_i))
   vault_spk_i = OP_1 <vault_key_i>      // funded with lot_im_sats native at issuance
   ```
   - **`premium = MIN_SETTLE_OUTPUT` is pinned and vestigial.** A tokenized lot is *minted*, never
     *opened* via the premium handshake, so its `terms_i.premium` is never paid — but
     `DifficultyContractTerms::Validate` rejects an OPTION `premium < MIN_SETTLE_OUTPUT` (= 546 sats,
     `src/consensus/difficulty_cfd.h`). The lot is pinned to exactly that floor so Validate passes,
     and the value is **decoupled from `reference_premium_sats`** — otherwise the displayed premium
     would feed `contract_id` and move every vault address. (No new validation path; no consensus
     touch.)
   - **`writer_key` is the issuer's raw signable x-only key**, used directly as both the writer-leg
     settlement payout output key (`P2TR(writer_key)`) and the buy-back leaf signing key. It is NOT a
     covenant/NUMS key. The option vault drops the coop leaf, and the buy-back leaf intentionally
     reveals the writer's real key so the issuer can sign with the key it already holds. A
     self-issuance issuer controls this key; under bilateral it is still the writer's key.
   - **Tap-tree shape is exact**: the two `Add(depth=1, …)` calls + `Finalize(NUMS_H)` are the
     normative D1-b construction. Leaf order does not affect the root (BIP341 sorts the branch pair),
     but leaf version `0xc0` and depth 1 do. D1-a uses a single depth-0 leaf.
   - **Buy-back spend signs an output-binding sighash.** The leaf's `OP_OUTPUTMATCH_ASSET` forces the
     1-unit-to-`sink_i` retirement output, but the wallet builder MUST sign the writer's
     `OP_CHECKSIGVERIFY` with an output-binding sighash (`SIGHASH_DEFAULT`) — the script cannot
     enforce sighash, and a non-binding signature would let a third party maul the rest of the tx.

`cp_key_i = pot_key_i` is the keystone: settlement pays the ITM leg to `OP_1 <pot_key_i>`, which is
exactly `pot_i`'s address (`OPTION_TOKENIZATION.md` §1.1, §2.7). No circularity: every value flows
from `series_id = H(descriptor)`, and the descriptor holds only base params + `series_salt`.

---

## 5. Settlement / redemption shapes

These are fully determined by §4 + existing consensus.

- **Settlement** (per lot, one tx, `BuildOptionSettlementSkeleton`): recomputes the split via
  `ComputeDiffCfdPayout` (clamped floor + 546-sat dust-snap) and reconstructs the control block from
  the §4 tree. ITM → `OP_1 <pot_key_i>`; OTM omits the zero leg. The builder DERIVES the lot and
  requires the funded vault UTXO to BE the derived vault (scriptPubKey == derived, value == per-lot
  IM, native-only). The settlement tx carries `nLockTime == settle_lock_height` and a signatureless
  witness `[settle_leaf, control]`.
- **Redemption** (batched, `BuildOptionRedemption`): each `pot_i` input witness = `[pot_leaf_i,
  control]` (no signature); one output `sink_spk_i : dust + AssetTag(asset_id, 1)` per lot, built with
  the shared 2-arg `BuildAssetTagTlv` (`src/assets/asset.h`). Unique sinks ⇒ one-token-one-pot. The
  builder verifies every input from its `txout` (pots: derived spk, native-only; token inputs: carry
  `AssetTag(series_id)`, units summed from the actual vExt; native fee inputs: native-only), enforces
  the asset-per-tx (64) and total-output (128) policy caps, and rejects duplicate input outpoints.
- **Buy-back** (D1-b only, `BuildOptionBuyback`): the writer's early unwind. As redemption but for one
  vault — spends it via the buy-back leaf (witness `[<placeholder sig>, buyback_leaf, control]`; the
  wallet signs `OP_CHECKSIGVERIFY` with an output-binding sighash), retires 1 unit to the lot sink,
  and returns token change (`m − 1`) plus reclaimed collateral to the writer. Fails on a settle-only
  lot.

---

## 6. ICU payload layout + metadata bands

The ICU payload (`src/assets/icu_payload.h`) is **plaintext** for an option series (publicly
verifiable — not keywrapped). Three slots:

- `canonical_text` (bound by `canonical_hash = SHA256(canonical_text)`) — the **operative** human
  option-terms document, rendered as-is. The only binding human terms.
- `metadata` (raw bytes, `icu_payload.h:64`) — the **typed-band container** (§6.1).
- the whole payload is sealed by `icu_ctxt_commit`.

For a series, `optionseries.build_register` populates `canonical_text` with a readable terms summary
and `metadata` with the canonical `TSC-ICU-META-1` band (`BuildOptionSeriesIcuMetadata`).

### 6.1 `TSC-ICU-META-1` container (canonical JSON)

```jsonc
{ "spec": "TSC-ICU-META-1",
  "optseries": { "spec": "TSC-ICU-OPTSERIES-1", "parse_version": 1,
                 "descriptor": "<hex of the EXACT §2 bytes>" },
  "termsheet": { "spec": "TSC-ICU-TERMSHEET-1", "parse_version": 1, /* §6.3 */ } }
```

The serialized container bytes ARE committed (they sit in `payload.metadata`, sealed by
`icu_ctxt_commit`), so two implementations must emit *identical* bytes or the commitment diverges.
`CanonicalizeIcuBandJson` (`src/assets/icu_payload.cpp`) is the one shared encoder used by both the
writer and every verifier. It guarantees: object keys sorted lexicographically (recursively),
duplicate keys rejected; minimal separators (`,`/`:`, no spaces); integers only — canonical decimal,
matching `^-?(0|[1-9][0-9]*)$`, so floats, exponents, leading zeros, `-0`, and `NaN`/`Inf` are
rejected; strings escaped to the canonical JSON string form; arrays in source order. This is a
wallet/RPC helper — **not consensus**. `geticupayload` surfaces the whole container; a renderer pulls
a band by `spec`.

### 6.2 `TSC-ICU-OPTSERIES-1` — the machine descriptor band

`descriptor` MUST be the **exact §2 bytes** (hex), the same string fed to §3's `TaggedHash` — NOT a
JSON re-encoding of the fields. A semantically-equivalent object would reopen the exact-byte
reproduction problem and break `asset_id` recompute. To verify a series, a verifier hex-decodes
`descriptor`, recomputes §3, asserts `== asset_id`, then runs §4 to re-derive and check all N vaults
on chain (`OPTION_TOKENIZATION.md` §3 checklist). `ExtractDescriptorFromIcuMetadata`
(`option_series.cpp`) does this fail-closed: it re-canonicalizes the supplied bytes and rejects
anything that is not byte-identical to the committed on-chain form, then asserts the band identity
(`spec` / `parse_version`) before returning the descriptor.

### 6.3 `TSC-ICU-TERMSHEET-1` — non-operative human summary

A machine index/summary over `canonical_text` for wallet/explorer rendering — **never** a second
binding document (`OPTION_TOKENIZATION.md` §6.5 hard boundary). Auto-derived from §2 fields so it
cannot drift (`BuildOptionSeriesIcuMetadata`). Fields:

```jsonc
{ "spec":"TSC-ICU-TERMSHEET-1", "parse_version":1,
  "option_kind":"call" | "put",
  "strike_nbits":<u32>, "fixing_height":<u32>, "settle_lock_height":<u32>,
  "lambda_q":<u32>, "lot_count":<N>, "lot_im_sats":<u64>,
  "reference_premium_sats":<u64>,            // display only; see §2 / OPTION_TOKENIZATION §6.1
  "payout_cap_per_lot_sats":<lot_im_sats>,   // covered option: payout ∈ [0, im]
  "disclosures":[ "covered-call-not-future" | "covered-put-not-future",
                  "zero-writer-default-risk", "decimals-0" ] }
```

Premium and termsheet are **not** part of backing verification (§3 / `OPTION_TOKENIZATION.md` §3);
backing = N vaults + mint + cap, on chain.

---

## 7. Conformance vectors

A cross-implementation conformance set, generated from the fixed example inputs below and asserted in
`src/wallet/test/option_series_tests.cpp`. The independent Python generator
(`contrib/option_series/gen_freeze_vectors.py`, pure `hashlib` + quadratic-residue x-only check) and
the C++ derivation agreeing IS the conformance guarantee.

### 7.1 Example inputs (self-issuance, D1-b)

```
descriptor_version=1  issuance_mode=0  leaf_set=1
writer_key         = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798  (secp256k1 G.x; valid x-only)
strike_nbits       = 0x1d00ffff
fixing_height      = 150000
settle_lock_height = 150100
lambda_q           = 218453            (Q16)
lot_im_sats        = 3000000000        (30 TSC; K=3000 TSC, N=100)
lot_count (N)      = 100
reference_premium_sats = 50000000000   (500 TSC; display only)
series_salt        = 1d59c4b99e941c31d184cf90f76bde031aa142ce855c37b9cd887004baf86f52
                     (= SHA256("OPTION_SERIES_FREEZE example v1"))
```

### 7.2 Identity vectors (pure SHA256 + secp256k1 field test)

These pin the highest-churn identity bytes — the descriptor layout (§2), the §3 tag, and the §4.1/§4.2
tags and counter-loop. Any drift in §2/§3/§4.1/§4.2 changes them.

```
descriptor (103B) = 01000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffff001df0490200544a020055550300005ed0b2000000006400000000743ba40b0000001d59c4b99e941c31d184cf90f76bde031aa142ce855c37b9cd887004baf86f52
asset_id          = c4ed91972ef3014baa1faccc37b7ec80f43cdd4cccf258ec25215371ccd5e96e
salt_0            = 14ab1739cea05cf202f22d1fc22dd7456be27cb24966419a4e102507f5e6c9ee
salt_1            = bb81c9b301ba11646171086ec9ffe45865248357d1d6368c96883a245d2a1351
salt_99           = da643369b580f9d917b0226a689f3288ad733cdbcbed1b4f4faafc5d2f06b650
sink_0  (ctr=2)   key = 161414ef412ed20bdea13af770a92ae8efdacf55dfbdeed4fb691f4aa525a82c
        spk = 5120161414ef412ed20bdea13af770a92ae8efdacf55dfbdeed4fb691f4aa525a82c
sink_1  (ctr=0)   key = c5c044a4284751ce4d8ad7f925ac222cedd3036fb62925c0a138ce12c8f0ac4d
        spk = 5120c5c044a4284751ce4d8ad7f925ac222cedd3036fb62925c0a138ce12c8f0ac4d
sink_99 (ctr=0)   key = 010072e463e0158c2db1814057b929bd14babf9d767afeee4e61b72bd20ba19e
        spk = 5120010072e463e0158c2db1814057b929bd14babf9d767afeee4e61b72bd20ba19e
```

### 7.3 Reference-impl vectors (real `ComputeDifficultyContractId` / `BuildDifficultyLeafScript` + consensus `TaprootBuilder`)

Emitted by `DeriveOptionLot` through the real difficulty-contract helpers and the consensus
`TaprootBuilder`; `leaf_set = 1` (D1-b), so every vault tap tree is settle + buy-back. Full leaf
vectors for the three sampled lots:

```
lot 0
  salt         = 14ab1739cea05cf202f22d1fc22dd7456be27cb24966419a4e102507f5e6c9ee
  contract_id  = 389fc5a66f69b6e25bf270a016df6df7dc47383a01f30246d461bebcb18164ab
  pot_key      = 69ed5b05f5d0cdb286d4bc4d2e605096cd6a381f97f3eb696888fab967f38430
  pot_spk      = 512069ed5b05f5d0cdb286d4bc4d2e605096cd6a381f97f3eb696888fab967f38430
  vault_key    = 093d8c9890b6fea0a2517e4015eb03a20f76b0bdedbea310a7c973f6f09c5d63
  vault_spk    = 5120093d8c9890b6fea0a2517e4015eb03a20f76b0bdedbea310a7c973f6f09c5d63
  settle_leaf  = 20389fc5a66f69b6e25bf270a016df6df7dc47383a01f30246d461bebcb18164ab7503544a02b17504f049020004ffff001d04555503005108005ed0b2000000002079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982069ed5b05f5d0cdb286d4bc4d2e605096cd6a381f97f3eb696888fab967f38430be
  buyback_leaf = 2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad20a5dbb5b6b805513f5560039ece27508611dd730de9fb6751b66b12a308ccb5f620c4ed91972ef3014baa1faccc37b7ec80f43cdd4cccf258ec25215371ccd5e96e080100000000000000b8
lot 1
  salt         = bb81c9b301ba11646171086ec9ffe45865248357d1d6368c96883a245d2a1351
  contract_id  = bc77e3a30d25447763d3edaff6085f17b3ede6617ebaf6824374cae658aff7da
  pot_key      = da278d5b096e0723a5bdb2d2ff6b06541842b11c4ccb3e8302f0e446b7f16445
  pot_spk      = 5120da278d5b096e0723a5bdb2d2ff6b06541842b11c4ccb3e8302f0e446b7f16445
  vault_key    = eea7f03826175f675450c3c73f3ec70f3ff3de65d02522d404386546fc9240d4
  vault_spk    = 5120eea7f03826175f675450c3c73f3ec70f3ff3de65d02522d404386546fc9240d4
  settle_leaf  = 20bc77e3a30d25447763d3edaff6085f17b3ede6617ebaf6824374cae658aff7da7503544a02b17504f049020004ffff001d04555503005108005ed0b2000000002079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179820da278d5b096e0723a5bdb2d2ff6b06541842b11c4ccb3e8302f0e446b7f16445be
  buyback_leaf = 2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad20c15e239f1444c75a12771b7583dbe54fc387d55e395ed4ca6ad4e42c4f10e9cf20c4ed91972ef3014baa1faccc37b7ec80f43cdd4cccf258ec25215371ccd5e96e080100000000000000b8
lot 99
  salt         = da643369b580f9d917b0226a689f3288ad733cdbcbed1b4f4faafc5d2f06b650
  contract_id  = 572c312ea94c9c149dcef0f05ee8f08a6c0008f63e5434a96a799c6c4693c751
  pot_key      = 3b6d50918405d27a02077b04b081f1fab3ef82126d9a97669feb16f30e587b99
  pot_spk      = 51203b6d50918405d27a02077b04b081f1fab3ef82126d9a97669feb16f30e587b99
  vault_key    = 0186e24f412829f8b3515551919b1c7c356c9d59ecb3bad9546267f265734051
  vault_spk    = 51200186e24f412829f8b3515551919b1c7c356c9d59ecb3bad9546267f265734051
  settle_leaf  = 20572c312ea94c9c149dcef0f05ee8f08a6c0008f63e5434a96a799c6c4693c7517503544a02b17504f049020004ffff001d04555503005108005ed0b2000000002079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798203b6d50918405d27a02077b04b081f1fab3ef82126d9a97669feb16f30e587b99be
  buyback_leaf = 2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad206ad381444fcdc62675b94f1b0c38d20ff7f7fe40012c64bc387c1b4682b68af820c4ed91972ef3014baa1faccc37b7ec80f43cdd4cccf258ec25215371ccd5e96e080100000000000000b8
```

The leaf structure is identical for all three lots (bytes differ only in `contract_id` / `cp_key` /
`tapmatch`). `settle_leaf` decodes to the difficulty-contract leaf —
`20<contract_id> 75 03<settle_lock> b1 75 04<fixing> 04<strike> 04<lambda> 51 08<im> 20<owner=writer_key> 20<cp=pot_key> be`
(trailing `0xbe` = `OP_DIFFCFD_SETTLE`); `buyback_leaf` decodes to the §4 form —
`20<writer_key> ad 20<tapmatch(sink_spk)> 20<asset_id> 08<1 unit> b8` (trailing `0xb8` =
`OP_OUTPUTMATCH_ASSET`).

---

## 8. RPC surface

Read-only **core** RPCs (any node, no wallet — `src/rpc/option_series.cpp` derive/verify path):

- `optionseries.derive` — given `terms`, returns the descriptor bytes, `asset_id` (both hex
  conventions), and the per-lot derivations.
- `optionseries.verify` — given a `source` (exactly one of `descriptor` hex, `icu_metadata` canonical
  bytes, or `terms`), recomputes `asset_id` and re-derives the backing vaults so a buyer can
  authenticate a series independently. `icu_metadata` is checked fail-closed against the committed
  canonical form.

Wallet-scoped RPCs (fund / broadcast):

- `optionseries.build_register` — register the asset shell for a series as a sponsored child
  `ROOT.SUFFIX` under an existing parent namespace (composes `sponsorchildasset`). Hard-sets the
  `OPTION_TOKENIZATION.md` §2.5 invariants: asset bytes == `series_id`; decimals 0; issuance cap N;
  `MINT_ALLOWED` with no burn; governance quorum 0 (immutable). The child ICU carries both the human
  terms summary and the canonical `TSC-ICU-META-1` band. Does NOT mint units.
- `optionseries.build_issue` — issue a registered, confirmed series (self-issuance): mints all N units
  to the writer AND funds the N derived lot vaults (`lot_im_sats` each) in one tx (composes
  `mintasset`), preserving the registry ICU commits by continuity. Rejects a bilateral descriptor.
- `optionseries.record_issue` — persist a confirmed issuance into the wallet (the N lot-vault
  outpoints, the issue txid, the current ICU outpoint), keyed by `series_id`
  (`DBKeys::OPTION_SERIES = "optseries"`, `src/wallet/walletdb.cpp`), so settlement / redemption can
  find the series after a restart.
- `optionseries.list` — list the persisted series, with terms in the exact shape the build RPCs
  accept.
- `optionseries.build_settlement` — build the keeper-driven, signatureless settlement tx for one lot
  vault. Reads the live vault UTXO, re-derives the lot, re-checks the UTXO, enforces fixing-height
  burial by `DIFFCFD_MATURITY_DEPTH` and an open settle CLTV, and recomputes the payout from the
  realized nBits at the fixing height. Returns a PSBT with the vault input finalized. A third-party
  keeper may pass `vault_outpoint` directly.
- `optionseries.build_redeem` — assemble a batched redemption tx (retire 1 unit to each lot sink to
  sweep the matching pots).
- `optionseries.build_buyback` — the writer's early-unwind spend via the buy-back leaf (D1-b only).

All wallet RPCs validate `terms` through `ValidateOptionSeriesTerms` and compute `series_id`
internally from `terms`; a caller-supplied id is never trusted.

---

## 9. Persistence integrity

A persisted `OptionSeriesRecord` is a fully-issued series snapshot. `ValidateOptionSeriesRecord`
(`src/wallet/option_series.cpp`) gates every load and every `RegisterOptionSeries`: the terms must
pass `ValidateOptionSeriesTerms`; `series_id == ComputeOptionSeriesId(terms)` (and, on load, equals
the DB key); `issue_txid` is non-null; the ICU successor and every lot vault are outputs of
`issue_txid`; and `lot_vaults` is exactly `lot_count` outpoints, none null, none duplicated. A
mismatched or forged id, or a malformed vault set, can never enter the wallet's series map.

---

## 10. Change control

- Any change to §2 (fields/order/width) or §4 (derivation tags/algorithm) is a `descriptor_version`
  bump and needs fresh §7 vectors. The §3 asset-id tag stays fixed across descriptor versions (the
  version byte + descriptor length give collision-freedom — see §3); the tag changes only if the tag
  scheme itself is revised. v2 (directional, 104 bytes) reuses the v1 tag.
- D1 is recorded in-band (`leaf_set`), so a new leaf-set option is a new `leaf_set` value, not a
  version bump — but the new tree shape still needs vectors.
- Band schemas (§6) version independently via their own `parse_version`; a renderer must tolerate an
  unknown `parse_version` by presence-gating (skip, don't fail).
