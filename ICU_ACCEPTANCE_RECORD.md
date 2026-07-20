# ICU Acceptance Record (on-chain holder acceptance, `0x40` vExt)

Persists a holder's affirmation of an asset's ICU governance document — and optionally specific clauses —
**on chain**, instead of an off-chain BIP-322 sidecar. The acceptance is durable, tamper-evident, and
verifiable from chain data (plus, for one family, a holder-retained proof).

This complements the older off-chain flow (`icu.acceptance.prepare` / `icu.acceptance.verify`, which emit an
`OP_RETURN(document hash)` + an off-chain signature). The record here is a structured, self-describing
`0x40` vExt object with its own create / verify / list RPCs.

---

## 1. Carrier — the `0x40` vExt TLV

- The record rides in an output's `vExt` as TLV type **`0x40` (ICU_ACCEPTANCE)**, a freestanding output —
  **not** a sub-TLV on the asset output (vExt is single-TLV / exact-length per output), mirroring
  `TFR_ANCHOR` (`0x21`).
- The canonical carrier output is a **zero-value, unspendable `OP_RETURN`** anchor (`nValue == 0 &&
  scriptPubKey.IsUnspendable()`).
- Three consensus/relay gates that previously rejected an unknown vExt now accept a **well-formed** `0x40`:
  `ConnectBlock` (`validation.cpp`), `CheckTxInputs` (`consensus/tx_verify.cpp`), and `IsStandardTx` relay
  (`policy.cpp`, with a `MAX_ICU_ACCEPTANCE_VEXT_BYTES` size cap). They accept it **iff it parses** —
  the parser is fail-closed (below) — so consensus never stores garbage `0x40`.
- This is a consensus **relaxation = hard fork** (old nodes reject `0x40`). It is deployed **fleet-wide**
  rather than gated by a separate activation height, and rides the existing assets-activation gate.
- **Verify-on-read:** consensus does not validate the signature; it only whitelists the structurally +
  semantically valid record. Cryptographic validity is an RPC/read-layer concern.

---

## 2. Record format (`src/assets/icu_acceptance_record.{h,cpp}`)

Payload, deterministic little-endian, carried inside the `0x40` TLV:

| field | bytes | notes |
|---|---|---|
| `version` | 1 | = 1 |
| `mode` | 1 | 1 = acknowledge, 2 = return |
| `flags` | 2 | reserved, must be 0 |
| `asset_id` | 32 | |
| `icu_plain_commit` | 32 | the accepted canonical document hash |
| `holder_prevout_txid` | 32 | the asset UTXO the holder controls (binds the acceptor) |
| `holder_prevout_vout` | 4 | |
| `holder_spk_hash` | 32 | `SHA256(prevout scriptPubKey)` |
| `accepted_units` | 8 | cross-checked against the prevout's asset amount |
| `sig_scheme` | 1 | see §4 |
| `body_refs` | compactsize + 32·n | affirmed clause keys (raw digests), strictly ascending |
| `sig` | compactsize + m | per scheme (§4) |

**Fail-closed parse** (`ParsePayload` → `ValidateIcuAcceptanceRecord`): rejects bad version, unknown
`mode`, non-zero `flags`, unknown `sig_scheme`, unsorted/duplicate `body_refs`, scheme/length mismatch,
null required hashes, `accepted_units == 0`, and the **mode/scheme coupling** (ACK must be signed; RETURN
must be unsigned and carry no `body_refs`). Trailing bytes are rejected.

---

## 3. Signing message — `TSC-ICU-ACCEPTANCE-RECORD-1`

`IcuAcceptanceRecordSigningMessage(rec)` is a deterministic, domain-separated string binding **every field
except the signature** (version, mode, flags, asset_id, icu_plain_commit, holder prevout + spk hash,
accepted_units, sig_scheme, body_refs). The holder signs **this**, so a signature commits to the exact
prevout / units / scheme / document / clause set and **cannot be lifted** onto a different record.

---

## 4. Signature schemes — family-aware

The holder's scriptPubKey family decides the scheme:

- **`SECP_SCHNORR_RAW`** — a raw BIP-340 Schnorr over `TaggedHash("TSC-ICU-ACCEPTANCE-RECORD-1", message)`
  (64 bytes), verified against the **taproot output key** extracted from the prevout spk. Used for **both**
  taproot families:
  - **P2TR-v1** — output key already on chain, no extra exposure.
  - **P2TR-v2 / PQ** — key-path is consensus-disabled, so revealing/using the secp output key is
    quantum-safe (breaking it cannot spend; the ML-DSA tapscript is the only spend path). **ML-DSA is the
    spend authority only; it is never the acceptance signature.**
- **`SECP_BIP322_HASH`** — commit-reveal for **hash-hidden, spendable** families (P2PKH / P2WPKH / P2WSH).
  The holder makes a BIP-322 proof over the message; only `SHA256(proof)` is committed on chain (the pubkey
  is **not** revealed while the asset is held — quantum-safe). The proof (the base64 signature string's
  bytes) is returned as `revealed_bip322_proof` for the holder to **retain** and reveal at verify time.
- **`NONE`** — RETURN only; attribution is the asset-input **spend**, not a message signature.

> There is deliberately no full-on-chain BIP-322 scheme and no ML-DSA scheme: taproot uses the compact raw
> Schnorr; hash-hidden families use the hash commit-reveal (a full proof would expose a live key).

---

## 5. RPCs

### `icu.acceptance.record.create <asset> <mode> [options]` (wallet)
- **acknowledge:** taproot holder → `SECP_SCHNORR_RAW`; hash-hidden holder → `SECP_BIP322_HASH`
  commit-reveal (returns `revealed_bip322_proof`). The asset UTXO is left **unspent**.
- **return:** any holder family → spends the holder UTXO, sends `accepted_units` to the issuer's ICU return
  address, and carries a `NONE` record.
- Fail-closed: for a context-bearing asset, refuses to sign unless the committed payload is readable and
  `plain_commit_verified`; auto-affirms all designated clauses for a `required` context.
- This path **holds the holder key** (the Core wallet signs). For non-custodial clients use prepare/assemble below.

### `icu.acceptance.record.prepare` / `icu.acceptance.record.assemble` (node — keyless, non-custodial)
Two **keyless node RPCs** that let a client produce an acceptance **without the key ever leaving the client**
(matching the wallet's PSBT send model):
- **`prepare <asset> <mode> <holder_txid> <holder_vout> [options]`** — resolves the holder prevout, registry
  `icu_plain_commit`, family→scheme, and context `body_refs` (same fail-closed rules as create; holder-only
  context needs `options.dek`), builds the unsigned record, and returns `message_to_sign` + `signing_hash` +
  `scheme` + `holder_address` + all record fields. No keys.
- Client signs `message_to_sign` **locally** (BIP-322 for hash-hidden families; raw Schnorr over
  `signing_hash` for taproot) with its own holder key.
- **`assemble <record fields> <signature>`** — re-verifies the client signature (`VerifyIcuAcceptanceRecordSchnorr`
  / `VerifyIcuAcceptanceCommit` + `VerifyBIP322Signature`) and `body_refs ⊆ context`, builds the byte-identical
  `0x40` carrier, and returns an **unfunded carrier-only `rawtx`** (+ `revealed_bip322_proof` to retain). The
  client then funds it (`fundrawtransaction` **preserves** the vExt carrier — tested), signs the fee inputs
  locally, and broadcasts. `assemble` rejects a tampered/garbage signature (RPC error -8).

### `icu.acceptance.record.verify <txid> <vout> [options]` (node — no wallet required)
A **node RPC** (lives in `rawtransaction.cpp`), so a hoster on `-disablewallet` can notarize. The
`body_refs` context is read node-side via `ResolveIcuContext` (`CoinsTip().ReadIcuPayload` + plain-commit
verify + inline/metadata context extraction); for a **holder-only** context-bearing ACK, pass
`options.dek` (32-byte hex asset DEK) so the node can read the committed context — without it, that case
**fails closed** (`body_refs_ok=false`), the same strict answer the wallet path gave.
Fetches the tx **from the node** (mempool / block / `-txindex`; `options.blockhash` avoids `-txindex`) — an
unpublished tx cannot verify — reads the record from `vout[vout].vExt`, and checks:
- **`acceptance_mined`** — the tx is in a block **in the active chain** (reorg-aware; stale blocks fail).
- **`carrier_shape_ok`** — zero-value unspendable carrier.
- **`asset_registered`** + **`doc_current`** (informational; a rotated document does NOT invalidate history).
- **holder binding** — prevout resolved live or historically (`-txindex`); `SHA256(spk)==holder_spk_hash`;
  units match.
- **`signature_valid`** — `SECP_SCHNORR_RAW`: BIP-340 vs the output key. `SECP_BIP322_HASH`: requires
  `options.revealed_bip322_proof`, checks both the `H(proof)` commitment and real BIP-322 over the message
  vs the holder address. `NONE`/return: this tx spends the holder prevout **and** sends the units to a
  **current-or-historical issuer ICU address** (rotation-durable; see §6).
- **`body_refs_ok`** — `body_refs ⊆` the committed context's designated clauses (+ all of them when the
  context is `required`); a no-context asset must carry no refs. For ACK on a payload-bearing asset, the
  context must be **read and validated** (require `plain_commit_verified`, reject `context_error`) or it
  **fails closed**.

`verified` = all of the above.

### `icu.acceptance.record.list <asset> [options]` (node — no wallet required)
Also a **node RPC**; runs each candidate through the same node-side verifier and forwards `options.dek` /
`options.revealed_bip322_proof` into each per-record verify. When `-icuacceptanceindex` (§6a) is enabled and
caught up, candidates come from the **asset index** (only the blocks holding that asset's records); otherwise
— no index, or the index is enabled but not yet caught up — `list` **falls back to a full block scan**, so it
never returns partial results. Stale/reorged index entries are skipped (the active block at that height no
longer holds that txid), and any that slip through are rejected by the verifier as not mined in the active chain.
Records return **verified-only** by default (`options.from_height` bounds the scan; `include_invalid=true`
returns all candidates, tagged with `verified` + `reason` + the per-check booleans). **Best-effort for
proof/DEK-dependent records:** a single `dek`/`revealed_bip322_proof` is applied to *every* candidate, so a
scan covering multiple commit-reveal (or holder-only) records — each needing its *own* material — cannot mark
them all verified; those surface under `include_invalid`. For per-record material, call `verify` per record.

---

## 6a. `-icuacceptanceindex` (optional scale)

An opt-in `BaseIndex` (`src/index/icu_acceptance_index.{h,cpp}`, off by default) that maps **`asset_id →
[record locations]`** so `list` avoids a full block scan. `CustomAppend` scans each block's outputs for a
`0x40` record and writes a key `asset_id || height(BE) || txid || vout(BE)` (big-endian ints → a prefix
seek on `asset_id` yields ascending `(height, txid, vout)`). It is a **candidate locator, not a verifier**:
there is **no `CustomRewind`** (like `txindex`) — entries from reorged-out blocks are left in place and are
harmless because `list` re-runs the full verifier, which rejects anything not mined in the active chain. Wired
in `init.cpp` (flag + global + start/stop) and `CMakeLists.txt`; needs full blocks (`AllowPrune()==false`).

---

## 6. Rotation-durable RETURN verification

A return sends the asset to the issuer's ICU address, which **rotates** (each mint moves `icu_outpoint`).
To stay durable, verify walks the `icu_outpoint` rotation chain backward — each ICU output carries
`ISSUER_REG` for the asset, and its creating tx spent the previous ICU output — collecting **every
current-or-historical issuer ICU script** (guard ≤ 1000), and accepts the return if its asset output goes
to **any** of them. The issuer controls all its historical ICU addresses, so a since-rotated address is a
valid return target; a third-party address is not in the chain and is rejected. Needs `-txindex` to resolve
spent ancestors.

---

## 7. Security / validation summary

- Signature binds the whole record (§3) — not liftable.
- Fail-closed parse at consensus + relay (§2).
- Verify proves on-chain provenance + active-chain mining + carrier shape + holder binding + signature +
  `body_refs ⊆ context`.
- RETURN: spend-attributed, must send units to a real (current-or-historical) issuer ICU address.
- ACK on a payload-bearing asset: must read+validate the context or fail closed (no verifier-dependent
  "verified", no decrypted-but-unverified trust, no malformed-context-as-plain).

---

## 8. Limitations / not yet done

- **Temporal holder-liveness (verify gap):** `verify` proves the holder binding + signature for the bound
  prevout, but does **not** prove that prevout was *unspent at the acceptance tx's block height*. So a
  former holder who kept the key could produce a record bound to a UTXO they no longer hold and have it
  verify the same as a legitimate acked-then-transferred record — they differ only temporally. Live-only
  `create`/`prepare`/`assemble` block the obvious path (you can't build the record once the UTXO is spent),
  but do **not** fully close it: a client could `prepare`/`assemble` while the UTXO is live, **transfer it,
  then broadcast the (already-built) carrier later** — the carrier doesn't spend the UTXO, so it stays
  broadcastable. Mitigations in place: live-only tooling + `verify` surfaces `holder_utxo_live` /
  `prevout_source` so consumers can treat a spent-prevout ACK with suspicion.
  Two real ways to close it (future work): (a) an outpoint→spender index so `verify` can check the holder
  UTXO was unspent at the acceptance height; or — cleaner, consensus-level — (b) make the acceptance tx
  **spend-and-recreate (anchor) the holder UTXO** (spend `U`, recreate the same asset/units to a holder
  address in the same tx): being mined then *proves* the holder controlled the asset at that height, and the
  holder keeps the asset. (b) changes the carrier shape (currently ACK leaves the asset UTXO unspent) and
  would apply to both the custodial and keyless paths.
- **Keyless RETURN** is not built: `prepare`/`assemble` accept `acknowledge` only. RETURN is the `NONE`
  scheme (spend-attributed, no record sig), so its non-custodial form is a plain spend-to-issuer PSBT + a
  keyless record — a separate follow-up. The keyless **taproot** raw-Schnorr `assemble` branch compiles and
  mirrors create/verify but is not yet exercised functionally (the P2WPKH BIP-322 path is).
- **P2WSH / P2SH** script (multisig) hash-hidden families are accepted by create but **not yet tested**
  (need a multisig fixture + script BIP-322). Tested families: P2TR-v1, P2TR-v2, P2WPKH, P2PKH.
- **Undecryptable `required` context, empty refs:** a verifier that cannot read a holder-only payload fails
  closed for any non-empty refs; the narrow empty-refs completeness case can't be confirmed without the
  payload (it's allowed). Fully enforced for readable/public assets.
- `list` defaults to a full block scan; run `-icuacceptanceindex` (§6a) for the asset-indexed fast path.
- `create` is **wallet-scoped** (it signs); `verify`/`list` are **node RPCs** (wallet-free, for hosters).
- **Qt:** holder-side Accept | Return (with confirmation), an **optional-context clause-selection picker**,
  an explicit **"Copy verification details"** button, and an issuer-side **"View Acceptances"** dialog (runs
  `icu.acceptance.record.list` for the selected asset → a table of height / mode / scheme / holder UTXO /
  units / doc-current / verified / reason, with a "show unverified" toggle + Refresh) are implemented. (A
  `required` context auto-affirms all clauses; a no-context asset has none. The proof is copied only on
  demand, not auto-placed on the clipboard.)
- **Commit-reveal retention:** the chain commits to the exact `revealed_bip322_proof` bytes — losing them
  means the acceptance can't be verified later (re-signing may not reproduce the same bytes).

---

## 9. Test coverage

- **Unit** (`src/test/icu_acceptance_tests.cpp`): record serialize/parse roundtrip, fail-closed semantic
  validation, TLV wrap/unwrap, signing-message binding, `SECP_SCHNORR_RAW` sign/verify (incl. real tweaked
  P2TR output key), commit-reveal hash check, and `CheckIcuBodyRefsAgainstContext` (the `⊆`/required/
  no-context negatives).
- **Functional** (`test/functional/feature_icu_acceptance_record{,_create}.py`): carrier relay+mine +
  malformed reject; taproot-v1 ACK create→verify; post-transfer historical (txindex); rotation-durable
  multi-hop RETURN; adversarial-return rejection; verified-only `list` + `include_invalid`; Option-A
  inline-context required `body_refs`; P2TR-v2 ACK; P2WPKH + P2PKH commit-reveal; and a **wallet-free**
  check that `verify`/`list` resolve on a real `-disablewallet` hoster node whose `list` is served from
  `-icuacceptanceindex` (the index fast path).
- **Not cheaply reachable** through normal flows (noted, not faked): corrupted-registered-payload
  (`plain_commit_verified=false`) and `context_error` read-gate negatives.
