# Difficulty Derivative — Native nBits-Settled Bilateral CFD

A margined, cash-settled bilateral CFD whose underlying is **network difficulty** (the
chain's `nBits` target) read at a committed ancestor height. Both legs post Initial Margin
(IM) into independent Taproot vaults; at maturity each vault settles its own posted margin
as a deterministic, capped function of realized difficulty versus a strike. Settlement is
enforced by two consensus opcodes — `OP_NBITS_AT` (`0xbd`) and `OP_DIFFCFD_SETTLE` (`0xbe`)
— plus a transaction-wide one-difficulty-input rule, all active from genesis. A wallet/RPC
layer (`difficulty.*`) builds, opens, settles, and cooperatively closes these contracts,
including a single-margined-leg **option** variant.

## Design properties

- **Genesis activation, no soft-fork machinery.** Both opcodes are consensus-valid from
  height 0 and are removed from the `OP_SUCCESS` range unconditionally
  (`src/script/script.cpp` `IsOpSuccess`, which now begins at `0xbf`). This is a
  network-defining consensus rule: it exists before the genesis block of any chain that
  uses it, with no in-band upgrade path for an already-running chain. `MAX_OPCODE` is
  `OP_DIFFCFD_SETTLE` (`src/script/script.h`).
- **Two independent, self-settling IM vaults**, not a single pooled vault. Each vault
  settles *only its own posted margin* as a function of `nBits` at a committed fixing
  height `H`. Pooling would force symmetric, same-asset margin; two vaults preserve
  asymmetric IM, asymmetric leverage, and per-leg collateral. A vault never references the
  other vault — there is no cross-vault covenant or input binding. The only transaction-wide
  consensus addition is a one-difficulty-input cap (§2.3), enforced by a witness pre-scan.
- **Underlying is `nBits`** — the model-normalised network difficulty target — read at a
  **committed ancestor height `H`**, never at the settlement transaction's confirming block.
  Reading the confirming block would let the in-the-money party time settlement around
  retarget boundaries; a fixed buried ancestor makes the payoff deterministic once block `H`
  exists. (PoW validation itself uses `nAdjBits`; `nBits` is the normalized difficulty
  target, so `nBits @ H` is the correct, manipulation-resistant underlying.)
- **Consensus core is a refactor, not an opcode patch.** Opcodes, a witness-version guard,
  the witness pre-scan, the transaction-level cache bypass, and the `FixingContext` resolver
  are all genesis-active. The full-script validity cache lookup runs *before* script checks,
  so the §3.3 pre-cache pre-scan slots in cleanly.

---

## 1. Economic Model

A margined, cash-settled **CFD on network difficulty**. Both parties post Initial Margin
(IM) into separate vaults. At maturity the payoff is a function of realized difficulty vs
a strike, bounded by posted margin (it is a *capped* CFD — IM is the max loss).

### 1.1 Per-vault loss fraction (the core primitive)

Do not denominate the payoff as a pooled "transfer of T TSC". Denominate each vault's
payout as a **fraction of its own IM** — dimensionless, hence asset-agnostic, requiring
no symmetry and no cross-asset price.

Let `K_target = SetCompact(strike_nBits)`, `S_target = SetCompact(realized_nBits at H)`.
Difficulty is the inverse of target, so in target space:

```
difficulty move = (K_target - S_target) / S_target = (difficulty_ratio - 1)
```

A vault pays out **only when its owner loses**:

```
long  vault (loses on difficulty DOWN, i.e. S_target > K_target):
    f_long_loss  = clamp( lambda_long  * (S_target - K_target) / S_target, 0, 1 )

short vault (loses on difficulty UP,   i.e. S_target < K_target):
    f_short_loss = clamp( lambda_short * (K_target - S_target) / S_target, 0, 1 )
```

Each vault's two outputs:

```
counterparty = floor( f_loss * vault_im )      # truncated; dust accrues to owner
owner        = vault_im - counterparty
```

`lambda = N / IM` is leverage; it is committed per-leg, so asymmetric leverage and
non-linear/asymmetric payoff curves come for free. Because everything is a fraction of the
vault's own IM, **non-native IM has no cross-asset pricing problem** — you win a fraction
of the counterparty's posted asset, denominated in that asset. (For different-asset legs
the bet is "fair" only at the off-chain price the parties used to pick `lambda`; consensus
only enforces the fractions. That is correct for collateralized bilateral risk.)

### 1.2 Why exact, not linearized

In target space `num/denom = (K_target - S_target)/S_target = K_target/S_target - 1 =
difficulty_ratio - 1 = the difficulty move`. A single 256→512-bit integer division
captures the reciprocal-of-target nonlinearity with **no approximation**. There is nothing
to linearize.

### 1.3 Worked example (locks the semantics)

`IM = 10 TSC = 1e9 sat` each side, `lambda = 10` (`lambda_q = 10 * 2^16 = 655360`, Q16,
`L = 2^16`). Convention: `1 TSC = 1e8 sat`.

| Case | move = num/denom | lambda*move | counterparty | owner | outputs |
|---|---|---|---|---|---|
| short leg, diff +5%  | 0.05 | 0.5      | 5e8 (5 TSC → long)  | 5e8 (5 TSC → short) | 2 |
| short leg, diff +10% | 0.10 | 1.0 (≥1) | 1e9 (10 → long)     | 0                   | 1 (cp only) |
| short leg, diff +12% | 0.12 | 1.2→clamp| 1e9 (10 → long)     | 0                   | 1 |
| short leg, flat/down | ≤0   | —        | 0                   | 1e9 (10 → short)    | 1 (owner only) |
| long  leg, diff −5%  | 0.05 | 0.5      | 5e8 (5 → short)     | 5e8 (5 → long)      | 2 |

Settle both legs (the winner runs both spends). Difficulty **+5%**:
- long vault → `{10 → long}` (f_long_loss = 0)
- short vault → `{5 → long, 5 → short}` (f_short_loss = 0.5)
- **Final: long 15, short 5.** ✓

Difficulty **+10%** (short fully liquidated): long 20, short 0. **−10%** (long fully
liquidated): long 0, short 20. No party delivers anything; no party loses IM merely for
being offline — IM is lost only when the realized move exhausts that party's margin.

---

## 2. On-Chain Architecture

### 2.1 Vault = Taproot output

Each IM vault is one Taproot output with a **NUMS (unspendable) internal key** and a taptree
of two script-path leaves:

```
Internal key = XOnlyPubKey::NUMS_H        ── key path is provably disabled
├─ Tapleaf: unilateral difficulty settlement (SCRIPT PATH)
└─ Tapleaf: 2-of-2 cooperative cosign       (SCRIPT PATH)
```

- **Unilateral settlement (script path):** `OP_DIFFCFD_SETTLE` (which resolves
  `nBits @ fixing_height` itself) gated by `CLTV ≥ H + burial`. This is the trustless
  enforcement floor: if cooperation fails, either party *or a third-party keeper* settles
  the formula outcome. It is signatureless (keeper-spendable) and reveals only this one
  leaf of this one vault.
- **Cooperative close (script path):** a 2-of-2 cosign leaf
  `<owner_internal> OP_CHECKSIGVERIFY <cp_internal> OP_CHECKSIG` over the two parties'
  internal payout keys. Either party can propose an early/negotiated split that bypasses the
  deterministic covenant — no maturity/burial wait — but it requires both signatures, so a
  cooperative close happens only by mutual agreement (signed via `difficulty.sign_coop`,
  §5). The unilateral covenant leaf remains the trustless fallback and is untouched by it.

Because the internal key is `NUMS_H`, the key path is unspendable; both spend paths reveal a
tapleaf. Vault output-key uniqueness is forced by committing `<contract_id> OP_DROP` (inert)
at the head of the settlement leaf — since all vaults share `NUMS_H`, the leaf is the only
thing that differentiates the taptweak, so two same-terms / different-salt contracts cannot
collide at the vault registry.

### 2.2 Unilateral leaf script

```
<settle_lock_height>  OP_CHECKLOCKTIMEVERIFY  OP_DROP   # belt-and-suspenders; consensus also enforces burial
<fixing_height_le4>
<strike_nbits_le4>
<lambda_q_le4>
<loss_direction_byte>
<vault_im_le8>
<owner_key32>
<cp_key32>
OP_DIFFCFD_SETTLE
```

All economic parameters are **committed literals inside the tapleaf** (hence in the
tapleaf hash and the output address) → tamper-proof at spend. The witness supplies only
the **revealed leaf script and its control block** — *no economic arguments and no
signature* (anyone-can-settle, enabling keepers).

**`realized_nbits` is resolved by consensus, not passed on the stack (folded).**
`OP_DIFFCFD_SETTLE` reads the committed `fixing_height` operand and resolves
`nBits @ fixing_height` itself via the `FixingContext` (§3.5) — it does **not** read a
realized value off the stack. This closes a forgery gap: an earlier design pushed
`realized_nbits` via a separate `OP_NBITS_AT`, but nothing bound the value `OP_DIFFCFD_SETTLE`
consumed to that opcode's output, so a committed leaf could embed a fake realized literal.
With resolution folded in, the realized difficulty is a pure function of the committed height
and the chain — unforgeable by construction. (`OP_NBITS_AT` remains a defined general-purpose
primitive; the difficulty leaf simply no longer relies on it.)

### 2.3 Per-vault output isolation — CONSENSUS rule (one difficulty input per tx)

**A relay rule is not enough: consensus fund-safety must not depend on it.** The §3.2
step-4 `consumed` set is local to *one* opcode evaluation, so it stops the owner and
counterparty entries of a single vault from sharing an output — but it cannot stop two
*separate inputs* (a miner-crafted tx co-spending both vaults) from each matching the same
output and underpaying. So this is a **consensus invariant, enforced from genesis**:

> **A transaction is invalid if more than one of its inputs spends a Taproot
> script-path leaf whose revealed tapscript contains `OP_DIFFCFD_SETTLE`.**

**Enforcement is a witness pre-scan, NOT script-execution metadata** — deliberately, to
avoid two traps: (i) `CScriptCheck::operator()` returns only *failure* metadata and
`CCheckQueue` keeps only the first error, so successful per-input "ran the opcode" data is
discarded; (ii) a full-script *cache hit* skips execution entirely, which would bypass any
execution-set flag (see §3.3). Instead, `CheckInputScripts` (in both `ConnectBlock` and
mempool `PreChecks`), *before/independent of* the parallel script checks, walks each
input's witness using **exactly the same Taproot extraction rules as `VerifyWitnessProgram`
/ `VerifyTaprootCommitment`** — strip the annex (`0x50` leading element when ≥2 stack
items), require the control block at the expected position with size
`33 + 32k` (`k ≤ 128`), read the **leaf version `0xc0`** tapscript as the second-from-top
element — then parses that leaf with `GetOp` (respecting push-data, so a `0xbe` byte inside
a push does not count) to test for `OP_DIFFCFD_SETTLE` as an opcode; it **rejects the tx if
the count > 1**. Sharing the extraction code with the verifier (not a hand-rolled re-scan)
is required so the scan and the interpreter agree byte-for-byte on what "the revealed leaf"
is.

**Witness version scope is an EXPLICIT check, not just `SigVersion`.** This fork's
witness-**v2** script-only Taproot also executes under `SigVersion::TAPSCRIPT`
(`script/interpreter.cpp`), and sibling covenant opcodes such as `OP_OUTPUTMATCH_NATIVE` gate
only on `SigVersion` — so "tapscript" alone does NOT mean v1. Therefore **both `OP_NBITS_AT`
and `OP_DIFFCFD_SETTLE` `FAIL unless execdata.m_witness_version == 1`** (rejecting v2
explicitly). Correspondingly the §2.3 pre-scan inspects only v1 (witness-program
length 32, leaf `0xc0`) script-path spends. A v2 leaf carrying the byte cannot execute the
opcode (it fails), so it cannot settle and need not be counted — counting it would still be
safe (over-count).

This "revealed" count is **conservative and sound**: the unilateral path can only be spent
by revealing that exact committed leaf, so reveal ⇒ (would-)execute; it can over-count an
opcode sitting in a dead `OP_IF` branch, which only ever *forbids* more txs, never permits
the sharing exploit. The cooperative cosign leaf does not contain `OP_DIFFCFD_SETTLE`, so a
cooperative spend is never counted (a cooperative close of either vault stays legal).
Because the scan is execution- and cache-independent, no cache hit can bypass it.

Settling a contract through the unilateral path is therefore always **two separate spends**,
one per leg — guaranteed by consensus, not by wallet behaviour or unique keys. The
standardness/relay rule (reject >1 such input) is kept only as a cheap pre-filter; it is no
longer load-bearing.

Within its single allowed difficulty input, `OP_DIFFCFD_SETTLE` still binds the owner and
counterparty payouts to **distinct outputs** by exact scriptPubKey + exact amount (§3.2
step 4). The covenant has **no aggregate-output semantics** and no knowledge of any other
input. A cooperative close negotiates the distribution off-chain and signs it with both
keys, so there is no covenant-sharing risk there and the one-input rule never constrains it.

### 2.4 Fees

Paid by the **broadcaster** from a separate native fee input; the covenanted IM split
stays exact (essential for non-native IM, where you cannot pay a native fee out of a
colored-asset vault). A keeper who broadcasts eats the fee. **No fee is ever deducted from
the IM split.**

### 2.5 Privacy ladder

- Cooperative cosign close → reveals only the 2-of-2 cosign leaf — no settlement formula
  and no fixing height; the distribution is whatever the two parties agreed.
- Unilateral, one vault at a time → reveals only that leg's settlement leaf (the winner can
  settle the loser's vault first, own vault later; this leaks one leg at a time and costs an
  extra spend).
- Unilateral, both vaults in one tx → **not available** (the one-input rule of §2.3 forbids
  it).

### 2.6 Settlement liveness

The unilateral leaf is covenant-only (keeper-spendable). The winning party has the
incentive to settle **both** vaults — recover own IM + claim winnings — which through the
unilateral path means **two separate transactions** (one per vault, per §2.3). The losing
party need never come online and still receives `IM − loss` at its committed address.
`CLTV ≥ H` plus required burial prevents settlement before the fixing is final.

---

## 3. Consensus Design

### 3.1 `OP_NBITS_AT` (0xbd)

```
in:   <fixing_height_le4>
out:  <nBits_le4>
rules:
  - v1 tapscript only: FAIL unless execdata.m_witness_version == 1 (v2 also runs as
    SigVersion::TAPSCRIPT, so check the witness version explicitly); requires FixingContext (§3.5)
  - the input blob must be EXACTLY 4 bytes; interpret as unsigned uint32 LE
    (NOT a CScriptNum — no sign bit, no minimal-push reinterpretation, no other length)
  - let H = that uint32; FAIL unless 0 <= H < FixingContext.ContextHeight()
    (range-checked to a valid int before any GetAncestor(int) call)
  - r = FixingContext.NBitsAt(H); FAIL if r == nullopt
  - push r as a 4-byte LE blob
```

`NBitsAt` resolves to `pindex->GetAncestor(H)->nBits` (block) or `tip->GetAncestor(H)->nBits`
(mempool) — reorg-consistent and a pure function of the confirming/tip ancestry (§3.5).

### 3.2 `OP_DIFFCFD_SETTLE` (0xbe)

Stack in **push order (bottom → top)** — i.e. exactly the order the §2.2 leaf pushes them.
All are committed literals; `realized_nbits` is NOT on the stack — `OP_DIFFCFD_SETTLE` resolves
it from `fixing_height` via the `FixingContext` (folded, §2.2):

```
bottom │ fixing_height_le4   (committed; settle resolves nBits @ H itself)
       │ strike_nbits_le4
       │ lambda_q_le4
       │ loss_direction_byte
       │ vault_im_le8
       │ owner_key32
top    │ cp_key32
```

`OP_DIFFCFD_SETTLE` therefore **pops top-first**: `cp_key32`, `owner_key32`, `vault_im`,
`loss_direction`, `lambda_q`, `strike_nbits`, `fixing_height` — then resolves
`realized_nbits = FixingContext.NBitsAt(fixing_height)` internally.

Fixed-point: `lambda_q` is `lambda` in **Q16** (`lambda = lambda_q / 2^16`), range
`[1, 2^32)`, so `L = 2^16`. `*_key32` are 32-byte Taproot output keys; expected
scriptPubKey = `OP_1 <key32>`.

**Stack-blob encoding (consensus, checked before decode — reject otherwise):**
`realized_nbits`, `strike_nbits`, `lambda_q` = exactly 4 bytes LE; `vault_im` = exactly
8 bytes LE; `owner_key32`, `cp_key32` = exactly 32 bytes; `loss_direction_byte` = exactly
one byte equal to `0x00` (long/down) or `0x01` (short/up) — *not* any truthy/falsy
`CScriptNum`. Exact lengths and encodings only; no minimal-push re-interpretation, no
sign-bit games. This removes settlement malleability.

```
0. CONTEXT GUARD
   FAIL unless execdata.m_witness_version == 1     # v1 tapscript only; v2 also runs as TAPSCRIPT

1. COMPACT DECODE (via FixingContext.DecodeTarget — wraps header DeriveTarget WITH the
   chain's powLimit, so the interpreter applies identical range rules to block validation
   without itself holding consensus params; see §3.5)
   K_target = ctx.DecodeTarget(strike_nbits)         # rejects negative/zero/overflow/>powLimit
   S_target = ctx.DecodeTarget(realized_nbits)       # same; value came from a validated header
   FAIL if either DecodeTarget returns nullopt
   # Canonicality: round-trip-check ONLY the strike literal (we choose it):
   FAIL unless K_target.GetCompact() == strike_nbits  # reject non-minimal / sign-bit strike
   # Do NOT round-trip realized_nbits: OP_DIFFCFD_SETTLE resolves it from the committed
   # fixing_height via FixingContext.NBitsAt (a chain-header value, not spender-chosen) →
   # no malleability. Requiring canonicality
   # on it would couple this opcode to a header invariant we are not assuming here.
   # (Recommended complementary invariant, separate from this opcode: enforce canonical
   #  nBits in header validation from genesis. Then the distinction is moot.)
   FAIL if lambda_q == 0
   FAIL if vault_im < MIN_SETTLE_OUTPUT              # see step 4 dust note; vault must be able to
                                                     #  emit at least one relayable output

2. LOSS NUMERATOR BY DIRECTION (denom = S_target)
   DOWN (long leg):  d = S_target - K_target        # long loses as difficulty falls
   UP   (short leg): d = K_target - S_target         # short loses as difficulty rises
   if d <= 0:                                        # in-the-money or flat
       payout_cp = 0 ; payout_owner = vault_im ; goto VERIFY
   num = d                                           # num > 0 (may exceed denom for >+100% moves;
                                                     #  the step-3 clamp handles that)

3. CLAMPED EXACT FLOOR (single floor; dust → the surviving leg)
   if  lambda_q * num  >=  L * denom:                # 512-bit compare → raw fraction ≥ 1.0
       payout_cp = vault_im                          # full liquidation
   else:
       payout_cp = MulDiv512(lambda_q * num, vault_im, L * denom)   # floor(λq·num·im / (L·denom))
   payout_owner = vault_im - payout_cp
   # DUST FLOOR (consensus constant MIN_SETTLE_OUTPUT ≥ network dust; relay-safety, see step 4):
   #   snap a sub-dust NONZERO leg to 0 and give it to the other leg, so no nonzero covenant
   #   output is ever below dust. Because vault_im >= MIN_SETTLE_OUTPUT (step 1), exactly one
   #   leg can be sub-dust at a time, so this is well-defined:
   if 0 < payout_cp    < MIN_SETTLE_OUTPUT: payout_cp = 0;    payout_owner = vault_im   # dust → owner
   if 0 < payout_owner < MIN_SETTLE_OUTPUT: payout_owner = 0; payout_cp    = vault_im   # dust → cp

4. OUTPUT-SET VERIFY  — via NEW helper VerifyDiffCfdOutputs (do NOT reuse OutputMatches:
   it matches by tapmatch-hash + amount and allows one output to satisfy many checks).
   required = {}
   if payout_owner > 0: required += (payout_owner, spk = OP_1‖owner_key32)
   if payout_cp    > 0: required += (payout_cp,    spk = OP_1‖cp_key32)
   consumed = {}                                    # distinct-output index set, per evaluation
   for each (amount, spk) in required:
       find an output index j with tx.vout[j].spk == spk (EXACT bytes)
                                and tx.vout[j].value == amount
                                and NOT tx.vout[j].HasAssetTLV()   # NATIVE-only, mirror OP_OUTPUTMATCH_NATIVE
                                and j not in consumed
       FAIL if none; else consumed += j
   # native-only: rejecting asset-tagged outputs stops an asset-TLV output with the same
   #   SPK + native amount from satisfying the native covenant (IM is native-only; see §8)
   # zero-skip: a 0-amount leg produces no required entry (OP_OUTPUTMATCH_NATIVE rejects 0)
   # extra outputs (broadcaster change / fee) are allowed
   # exact-SPK match + the `consumed` set ⇒ one output can never satisfy two entries within
   #   this opcode; the §2.3 consensus one-input rule handles cross-input sharing

5. INPUT BINDING
   FAIL unless checker.GetInputAmount() == vault_im  # NEW accessor — see source map; the value
                                                     #  exists in GenericTransactionSignatureChecker
                                                     #  ::amount but is private today

6. push 1   (VERIFY-style: any FAIL above aborts the script)
```

**Widths / 512-bit intermediate.** Do **not** assume a narrow powLimit — `SetCompact`
yields a full **256-bit** target, and regtest/other chains use much wider compact limits
than mainnet's `~2^224`. Bound generally: `num, denom ≤ 2^256−1`, `lambda_q ≤ 2^32`,
`vault_im ≤ 2^64`. Then the step-3 compare needs `lambda_q·num` (≤ `2^288`) vs `L·denom`
(≤ `2^272`) — past 256-bit. The MulDiv numerator `lambda_q·num·vault_im` reaches ~`2^352`,
so the product must accumulate in a **512-bit integer** (comfortable margin) before
dividing by `L·denom`. Implement `MulDiv512(a,b,c) = floor(a·b/c)` on `base_uint<512>` (or
256-bit limb split); **never truncate to 256 mid-computation**.

**Rounding:** single floor on `payout_cp`; the ≤1-sat remainder always accrues to the
vault **owner**. The clamp boundary (`lambda_q·num == L·denom`) resolves to full
liquidation.

### 3.3 Script cache

The full-script validity cache is **transaction-level** (`wtxid + flags`), so the fix is
transaction-level too. A tx that **reads chain difficulty** — i.e. reveals a leaf containing
`OP_DIFFCFD_SETTLE` (which resolves `nBits @ H` itself) or the standalone `OP_NBITS_AT` — must not
be served from / stored in that cache under the bare key, because a deep reorg can change
`GetAncestor(H)->nBits` and make the same `wtxid` evaluate differently ("max reorg depth" is not a
consensus assumption).

Mechanics: the §2.3 witness pre-scan already walks every revealed leaf **before the cache
lookup**. It is reused here — if any revealed leaf contains `OP_DIFFCFD_SETTLE` or
`OP_NBITS_AT`, the **cache lookup and the cache store are bypassed for the whole tx**. The
pre-scan runs before the lookup, so the difficulty read is detected before any stale hit can
be served.

**The one-input rule (§2.3) does not depend on the cache.** Its count comes from the
witness pre-scan, which runs in `CheckInputScripts` independent of (and regardless of) any
full-script cache hit — so a cached script-pass can never bypass the transaction-wide
`OP_DIFFCFD_SETTLE` count. (Had the count been driven by execution-set metadata, a cache
hit would skip execution and silently defeat it — which is precisely why §2.3 uses the
pre-scan.)

### 3.4 Genesis activation

No `IsDifficultyCovenantActive` gate. `0xbd`/`0xbe` are removed from the `OP_SUCCESS`
range and are enforced from height 0. The interpreter must have block context available at
height 0 (genesis has no ancestor `H < 0`, so any leaf would simply fail `OP_NBITS_AT`'s
height check — fine).

### 3.5 Fixing context — one abstraction for both block validation AND mempool

`OP_NBITS_AT` must resolve `nBits @ H` in two call contexts, so the checker must NOT carry
a raw `const CBlockIndex*` (it would be null in mempool and these spends would simply never
relay). Instead the checker holds a small **fixing resolver** interface:

```
struct FixingContext {
    // nBits of the block at absolute height H on the relevant chain,
    // or nullopt if H is not resolvable / not yet final in this context
    std::optional<uint32_t>      NBitsAt(int H) const;
    int                          ContextHeight() const;  // confirming (block) or tip (mempool) height
    // compact→target using THIS chain's powLimit (wraps header DeriveTarget), so the
    // interpreter need not carry consensus params; nullopt on negative/zero/overflow/>powLimit
    std::optional<arith_uint256> DecodeTarget(uint32_t nBits) const;
};
```

`DecodeTarget` is what lets `OP_DIFFCFD_SETTLE` (§3.2 step 1) apply the *same* range rules
as header validation without the interpreter holding `Consensus::Params`. Both opcodes
reach it through the checker's `FixingContext`.

Both resolvers apply the **same consensus burial bound** via the shared, unit-tested predicate
`DiffCfdFixingResolvable(H, ContextHeight, MATURITY_DEPTH)` = `0 ≤ H < ContextHeight ∧
H ≤ ContextHeight − MATURITY_DEPTH`:

- **Block validation (`ConnectBlock`):** resolver = the confirming `CBlockIndex`;
  `NBitsAt(H) = pindex->GetAncestor(H)->nBits`, gated by the bound with `MATURITY_DEPTH`. This makes
  **consensus** (not the leaf's CLTV) enforce burial: a settlement can only be mined at a confirming
  height ≥ `H + MATURITY_DEPTH`, so the fixing ancestor is always deeply buried. The leaf's CLTV
  remains as belt-and-suspenders / relay-timing.
- **Mempool policy (`AcceptToMemoryPool` / `PreChecks`):** resolver = the active chain tip;
  `NBitsAt(H) = tip->GetAncestor(H)->nBits`, same bound, so the fixing is buried/final before relay.

Both resolve to the *same* value for a given `(tx, H)` barring a sub-`H` reorg — which is
exactly why §3.3 marks these inputs non-cacheable. `BaseSignatureChecker` exposes the
resolver (default: a null context whose `NBitsAt` returns `nullopt` ⇒ `OP_NBITS_AT` fails
closed), so non-script callers are unaffected.

---

## 4. Source map (bcore/src)

| Area | File | Role |
|---|---|---|
| Opcodes | `script/script.h` | `OP_NBITS_AT=0xbd`, `OP_DIFFCFD_SETTLE=0xbe`; `MAX_OPCODE = OP_DIFFCFD_SETTLE` |
| OP_SUCCESS | `script/script.cpp` | `IsOpSuccess` excludes `0xbd`/`0xbe`; the success range begins at `0xbf` |
| Reject codes | `script/script_error.h` | `SCRIPT_ERR_DIFFCFD_{CONTEXT, HEIGHT, ENCODING, TERMS, OUTPUTS, AMOUNT}` |
| Interpreter | `script/interpreter.cpp` | both opcode bodies (v1 tapscript, leaf `0xc0`) + the `VerifyDiffCfdOutputs` helper for §3.2 step 4 (exact-SPK + distinct-output-index binding + reject `HasAssetTLV()` — native-only) |
| Payout math | `consensus/difficulty_cfd.{h,cpp}` | `ComputeDiffCfdPayout` (clamped 512-bit floor + dust-snap); `MIN_SETTLE_OUTPUT=546`, `DIFFCFD_LAMBDA_SCALE=2^16`, `DIFFCFD_MATURITY_DEPTH=100` |
| Wide math | `arith_uint256.{h,cpp}` | `base_uint<512>` for the exact 512-bit muldiv |
| Checker iface | `script/interpreter.h` | a `FixingContext` accessor (`NBitsAt` + `DecodeTarget` + `ContextHeight`) and a `GetInputAmount()` accessor on `BaseSignatureChecker` (defaults fail closed: null context → `OP_NBITS_AT`/`DecodeTarget` fail; no-amount → settle fails); `GenericTransactionSignatureChecker` carries a `const FixingContext*` |
| Block plumbing | `validation.cpp` | `ConnectBlock` builds a confirming-`pindex` `ChainFixingContext` and threads it `CheckInputScripts → CScriptCheck → checker` |
| Mempool plumbing | `validation.cpp` | `PreChecks` / `AcceptToMemoryPool` build a tip-based `ChainFixingContext` (so these spends relay); both pass `DIFFCFD_MATURITY_DEPTH` |
| Cache | `validation.cpp` | the tx-level (`wtxid+flags`) lookup runs before script checks; the §2.3 pre-scan bypasses both lookup and store for any tx that reads chain difficulty (§3.3) |
| Consensus 1-input rule | `validation.cpp` `CheckInputScripts` | witness **pre-scan** using the shared `VerifyWitnessProgram` extraction (annex strip, control-block size, leaf `0xc0`), `GetOp`-parsed; rejects a tx with >1 input revealing `OP_DIFFCFD_SETTLE` as `bad-txns-diffcfd-multiple-inputs` (§2.3) |
| Relay pre-filter | `policy/policy.cpp` | the same scan as a cheap standardness pre-filter (not load-bearing) |
| Compact decode | `chain.cpp` | header `DeriveTarget(nBits, powLimit)` / `GetCompact`, wrapped by `FixingContext::DecodeTarget` |
| Keyless vault leaf | `wallet/vaultregistry.{h,cpp}` | a covenant-only leaf is marked by an all-zero `signing_key` sentinel (`VaultLeafDescriptor::IsCovenantOnly()`); `Validate()` skips the key check, and the signing/key-cache paths skip such leaves. Backward-compatible (no serialization change). `VaultRole::DIFFICULTY_LONG/SHORT` |

`DIFFCFD_MATURITY_DEPTH` is ≥ the chain's worst-case reorg assumption; it appears in both
the mempool-policy bound (`H ≤ tip − MATURITY_DEPTH`) and the leaf
(`CLTV ≥ H + MATURITY_DEPTH`) so the fixing is final before settlement is relayed or mined.

---

## 5. Wallet layer

`src/wallet/difficulty_contract.{h,cpp}`, `src/wallet/vaultregistry.{h,cpp}`,
`src/wallet/rpc/difficulty.cpp`:

- `CovenantContractKind::DIFFICULTY` and `VaultRole::DIFFICULTY_LONG/SHORT`.
- `DifficultyLegTerms` (per vault: `im`, `im_asset`, `lambda_q`, and the committed x-only
  Taproot payout keys `owner_key` / `cp_key`; `loss_direction` is **derived from the leg**,
  not stored) and `DifficultyContractTerms` (two legs, `strike_nbits`, `fixing_height H`,
  `settle_lock_height`, `kind` ∈ {CFD, OPTION}, optional `premium`) with Serialize/Unserialize
  and a restart-safe `DifficultyContractRecord`. The record carries `salt` (so
  `contract_id = H(terms ‖ salt)` — identical trades do not collide), the vault `COutPoint`s,
  the internal keys, and `open_txid`, so settlement after a restart needs no UTXO rediscovery.
- **IM is native-only.** The unilateral covenant leaf settles native outputs only, so
  `propose`/`accept` reject any `im_asset` ≠ native. The `im_asset` field is kept for
  forward-compatibility but validated `== native`. (The day-1 premium, §6, is *not*
  covenant-settled and so may be any asset.)
- `Validate(err, pow_limit)` checks: native-only IM, non-zero λ, `im ≥ MIN_SETTLE_OUTPUT`,
  valid payout keys, canonical strike, strike within `powLimit` (mirroring consensus
  `DeriveTarget`), `fixing_height ≤ INT_MAX`, block-height CLTV, and an overflow-safe
  `settle_lock_height ≥ fixing + DIFFCFD_MATURITY_DEPTH`. For `kind == OPTION` it is
  kind-aware: exactly one writer leg is funded, the other leg must be empty, and
  `premium ≥ MIN_SETTLE_OUTPUT`; a CFD keeps both legs and forbids a premium.
- `CreateDifficultyVaultBuilder()` builds a leg's Taproot from the `NUMS_H` internal key plus
  the keyless settlement leaf of §2.2 and the 2-of-2 cooperative cosign leaf (§2.1) — two
  vaults, one per leg. `BuildDifficultySettlementSkeleton()` is the output-conserved core of
  `build_settlement`: one vault input with the keeper witness `[leaf, control]` (no
  signature), non-final sequence, `nLockTime == settle_lock_height`, and the exact covenant
  payout outputs computed via the same `DeriveTarget` + `ComputeDiffCfdPayout` path as
  consensus.
- Records persist via `WalletBatch::Write/EraseDifficultyContract` /
  `LoadDifficultyContractRecords`; `CWallet` exposes
  `Register/Load/Find/ListDifficultyContract`.

### 5.1 RPC surface (`difficulty.*`)

The lifecycle is bilateral and permissionless — there is no coordinator and no escrow.

- **`difficulty.propose`** — proposer defines the full economics, their side, and their two
  P2TR payout keys; returns a stateless offer blob with a random salt.
- **`difficulty.accept`** — acceptor supplies their two keys; the four keys are slotted by
  role, the full terms validated, `contract_id = H(terms ‖ salt)` computed, and (with
  `confirmed=true`) the record persisted and an acceptance blob returned. Without `confirmed`
  it is a review call that returns the `contract_id` only.
- **`difficulty.import_acceptance`** — proposer reconstructs the full terms from its offer +
  the acceptor's keys, recomputes and verifies `contract_id` against the acceptance, and
  persists the identical record. Both wallets now independently hold the same record.
- **`difficulty.build_open`** — per-leg PSBT-augmenting atomic co-sign. The first party funds
  only its IM vault and returns a partial PSBT; the counterparty augments the same PSBT to
  fund the other vault (after verifying the committed vault scriptPubKey + amount), each signs
  its own inputs, and one atomic transaction funds both vaults so neither party fronts the
  other's margin. Both vaults are registered in each wallet. It also pays the optional day-1
  premium as a plain output in the same PSBT.
- **`difficulty.record_open`** — both parties call this post-broadcast to resolve and persist
  the two vault outpoints (the first party cannot know the final txid at `build_open`),
  enabling either party to settle.
- **`difficulty.build_settlement`** — finds the record, resolves `nBits @ fixing_height` under
  `cs_main`, enforces burial (`H ≤ tip − DIFFCFD_MATURITY_DEPTH`), verifies the vault UTXO
  exists and is unspent and is the record's vault (reconstructed output key, `nValue == leg.im`,
  native), builds the settlement skeleton, and funds it via `CCoinControl` over the keyless
  covenant input (`EstimateTaprootScriptPathInputWeight`, zero signatures) plus an external
  native fee input + change. It finalizes the keyless covenant input directly
  (`final_script_witness = [leaf, control]`) and leaves the fee input for the keeper to sign.
- **`difficulty.finalize_settlement`** — extracts the network transaction from a fully-prepared
  settlement PSBT. This is needed because `OP_DIFFCFD_SETTLE` cannot be verified without a
  chain fixing context, so `finalizepsbt` reports the covenant input non-final and refuses to
  extract. It is **scoped, not a generic unsafe extractor**: it skips verification only for
  inputs whose finalized leaf reveals `OP_DIFFCFD_SETTLE` and is BIP341-committed by the spent
  v1-Taproot output (`IsCommittedDiffCfdCovenantInput`: tapleaf-hash / merkle-root recompute +
  `CheckTapTweak`, control-block shape validated). A forged witness carrying an uncommitted
  `OP_DIFFCFD_SETTLE` leaf falls through to mandatory `PSBTInputSignedAndVerified` and is
  rejected; every other input must verify normally, and ≥1 committed covenant input is required.
  The node re-validates the transaction with the real fixing context on `sendrawtransaction`.
- **`difficulty.build_coop_close`** / **`difficulty.sign_coop`** — the 2-of-2 cooperative close.
  `build_coop_close` builds the agreed-split close transaction (vault input → agreed outputs,
  vault funds the fee) and annotates the vault input. `sign_coop` adds each party's half as a
  raw Schnorr tapscript partial-sig over the cosign leaf
  (`<owner_internal> CHECKSIGVERIFY <cp_internal> CHECKSIG`) — signed directly from the party's
  own payout-address signing provider rather than `walletprocesspsbt`, which would skip a
  covenant input the wallet does not own; the second `sign_coop` assembles the witness and
  returns the broadcastable hex. Both verify `vault_txout.nValue == leg.im`.
- **`difficulty.propose_option` / `accept_option` / `build_open_option`** — the option variant
  (see §6).

Difficulty CFD and option contracts also appear in the generic `contract.list` /
`contract.status` RPCs, each entry exposing `type=difficulty`, `kind` (cfd/option), `role`
(long/short, or writer/buyer), `status` (accepted/opened), the strike, fixing/lock heights,
per-leg `im`+`lambda`, option `premium`+`writer_side`, and the funded vault outpoints +
`open_txid`.

---

## 6. Difficulty options & the day-1 premium (no consensus change)

The base instrument is a symmetric, zero-cost-to-enter CFD. A **day-1 premium** turns it into
an asymmetric / option-style position with **no opcode or consensus change**, because a
premium is an ordinary output in the atomic open transaction, not part of any settlement
covenant. The premium is committed in `contract_id` (the contract hashes the terms).

- **Premium** in `DifficultyContractTerms`: a native-sat amount (`premium`, which must be 0
  for a CFD and ≥ `MIN_SETTLE_OUTPUT` for an option), paid **day 1** as a normal output inside
  the co-signed `build_open` PSBT, atomic with vault funding. Non-refundable; not escrowed.
  Because the premium is an ordinary output and not covenant-settled, it carries no settlement
  asset restriction beyond the schema's native amount.

Two shapes fall out of how many vaults are funded:

- **Option = ONE writer vault + premium.** Only the writer funds a collateral vault; the buyer
  posts no settlement IM and pays the premium. Buyer's max loss = premium; upside = up to the
  writer's full IM. Settlement is a single `OP_DIFFCFD_SETTLE` input (`owner = writer`,
  `cp = buyer`), fully covered by the existing opcode and the §2.3 one-input rule (count = 1).
  If difficulty does not favor the buyer, `f_loss = 0` → the writer's vault returns 100% to the
  writer (clean expiry) and the buyer simply walks, down only the premium. This is a covered
  difficulty call/put. The dedicated `difficulty.propose_option` / `accept_option` /
  `build_open_option` RPCs run the writer/buyer handshake (each gives one payout key) and the
  atomic open (writer funds the IM vault, buyer funds the premium to the writer); settlement
  reuses `build_settlement` / `finalize_settlement` unchanged.
- **Asymmetric CFD = TWO vaults + premium.** Both post IM and a premium is exchanged day 1 to
  compensate for an off-market strike or asymmetric `λ_long ≠ λ_short`.

---

## 7. Security properties

- **Compact canonicality is scoped to the strike** (§3.2 step 1): the strike literal (chosen
  by the parties) is round-trip-checked; `realized_nbits` is accepted as-is via `DeriveTarget`
  because it is a single header-fixed value, not spender-chosen, so there is no malleability.
  The opcode therefore does not assume header validation enforces canonical nBits.
- **Reorg below `H`** changes the fixing. This is mitigated by `MATURITY_DEPTH` burial (in both
  the consensus bound and the leaf CLTV) and by the non-cacheable rule (§3.3). `MATURITY_DEPTH`
  is sized against the chain's worst-case reorg assumption.
- **No `CScriptNum` clamp issue**: amounts and `lambda` are handled as LE blobs and in the C++
  opcode (512-bit), never via `CScriptNum` arithmetic.
- **Keeper griefing is bounded**: covenant outputs are pinned, so a keeper can only effect the
  correct settlement; the only freedom is timing (closed by `CLTV`) and fee (the keeper pays).
- **One difficulty input per tx is a consensus rule** (§2.3), not relay-only — a block with a
  tx revealing >1 leaf containing `OP_DIFFCFD_SETTLE` is invalid. The witness pre-scan is
  cache- and execution-independent, so neither `CCheckQueue`'s discarded success metadata nor a
  full-script cache hit can defeat it. This closes the cross-input output-sharing exploit (the
  §3.2 `consumed` set covers only a single evaluation).
- **Mempool/block context parity** (§3.5): the tip-based and confirming-block resolvers return
  the same `nBits @ H`; the non-cacheable rule (§3.3) keeps a sub-`H` reorg from making a
  cached pass go stale.
- **Witness version is checked explicitly**: witness-v2 Taproot also executes as `TAPSCRIPT`,
  so both opcodes require `execdata.m_witness_version == 1` (§3.2 step 0) and the pre-scan
  inspects v1 only.
- **Dust / relay liveness**: exact nonzero covenant outputs could fall below the dust /
  ephemeral-dust thresholds. The consensus `MIN_SETTLE_OUTPUT` floor + the step-3 dust-snap +
  `vault_im ≥ MIN_SETTLE_OUTPUT` keep every nonzero covenant output at or above dust, so
  settlement always relays.

## 8. Extension points

The architecture leaves these doors open without changing the shipped consensus surface:

- **Non-native asset IM settlement** via an asset-aware output match (`OP_OUTPUTMATCH_ASSET`
  semantics). The two-vault design already supports different assets per leg; only the
  asset-aware settlement match would be added.
- **Fixed native settlement bounty** leaf variant to pay keepers.
- **Both-legs-in-one-tx unilateral** via a per-vault output tag committed into each matched
  output's Taproot tweak, binding an output to exactly one vault unconditionally (the current
  rule forbids co-spends instead).

---

## 9. Pricing & Marking (wallet-side valuation)

> Pure off-chain valuation — **no consensus dependency**. The on-chain settlement math
> (`ComputeDiffCfdPayout`, §3.2) is the *terminal payoff*; this section defines how the
> wallet **marks an open contract to market before settlement**, consistent with the
> forward/repo pricing framework (`src/wallet/pricing/`).

### 9.1 The pricing primitive is the difficulty RATIO `R`, not nBits and not the target

The consensus loss fraction divides by the **realized** target (the stochastic quantity),
not the strike (`difficulty_cfd.cpp`: `denom = realized_target`). So define

```
R  =  strike_target / realized_target  =  realized_difficulty / strike_difficulty
```

(`target ∝ 1/difficulty`, so the reciprocal flips strike↔realized). The covenant payout
fractions are then **piecewise-linear in `R`**:

```
short / up   leg cp-payout = IM · clamp( λ · (R − 1), 0, 1 )      # loses as difficulty rises (R > 1)
long  / down leg cp-payout = IM · clamp( λ · (1 − R), 0, 1 )      # loses as difficulty falls (R < 1)
```

with `λ = lambda_q / 2^16`. This is the load-bearing correction: because the payoff is
linear in `R` (hence in *difficulty*), **the modelled variable must be `R`/difficulty, not
the compact `nBits` and not the raw target.** Modelling the target would make the payoff a
convex function `clamp(λ(K/S−1))` of the modelled variable and reintroduce a
σ-dependent reciprocal convexity adjustment. We avoid all of that by declaring `R` the
log-normal martingale (see 10.3); no convexity correction is ever applied.

### 9.2 Payoff = capped call / put spread on `R`

`clamp(λ·x, 0, 1) = λ·[ x⁺ − (x − 1/λ)⁺ ]`, so each leg's loss is a **scaled vertical
spread** on `R`:

```
short cp-payout = λ·IM · [ Call_R(K=1)        − Call_R(K=1 + 1/λ) ]
long  cp-payout = λ·IM · [ Put_R(K=1)         − Put_R(K=1 − 1/λ)  ]   # strike floored at 0
owner-payout    = IM − cp-payout
```

(`Call_R`/`Put_R` are *undiscounted, forward* option values on `R`.) The clamp at `1`
falls out of the second leg of each spread: once `R ≥ 1 + 1/λ` the structure pays the full
`λ·IM·(1/λ) = IM` (full liquidation). For `λ < 1` the long-leg lower strike `1 − 1/λ < 0`
floors to a worthless put, i.e. that leg can never fully liquidate — correct, since `R ≥ 0`.

### 9.3 Model: log-normal `R`, Black-76, discount on the NATIVE TSC curve

`R` at the fixing height is modelled log-normal with **forward `F_R` = E[R]** and
horizon volatility `σ√τ`:

```
F_R = strike_target / forward_target            # forward_target from the difficulty forward curve (10.4)
σ   = difficulty vol surface @ horizon          # annualized vol of log R (10.4)
τ   = blocks_to_fixing · nPowTargetSpacing / SECONDS_PER_YEAR     # ACT/365
```

Each forward option value uses **Black-76 expressed as an undiscounted expectation** —
reuse `BlackScholes::Price(F, K, τ, r=0, σ, q=0, type)`, which returns
`F·N(d₁) − K·N(d₂)` (the `r=q=0` Black-Scholes call collapses to the forward Black-76
value `E[(R−K)⁺]`). **Discounting is applied separately and authoritatively by the native
TSC discount curve** at the `settle_lock_height` tenor — the difficulty forward curve is a
*forecast*, never a discount factor and never cash-and-carry market data:

```
df          = native_curve.GetDiscountFactor( (settle_lock_height − current_height) days )
MTM_long    = df · E[PnL_long]      ,  PnL_long  = (owner_long − IM_long) + cp_short
MTM_buyer   = df · E[cp_writerleg] − premium      # premium already paid at t0
```

`E[payout(R)] ≠ payout(E[R])` is exactly what makes the **option** correctly priced (time
value, vega, theta) where the point-forecast pricer returned ~0 for an OTM option.

**Exact default fallback.** When no vol surface is configured (`σ = 0`) *and* the forecast
comes from an arith target the pricer holds (the flat tip fallback, or an explicit
`forecast_nbits` override, or a reached fixing), the expected quote is settled through the
**exact consensus `ComputeDiffCfdPayout`** (512-bit floor + dust-snap), so the default
no-market-data path reproduces the prior deterministic pricer **bit-for-bit** — no
regression for wallets that have not set up a difficulty surface. The continuous Black-76
spreads are used only once a real model is present (a difficulty curve and/or `σ > 0`),
where the curve is itself a model input and sub-dust rounding is immaterial.

### 9.4 Market data objects (in `PricingContext`, mark/market tiered)

- **`DifficultyCurve`** — chain-global forward curve `horizon_blocks → E[D]` where `D` is
  difficulty in chainwork-per-block units (`DifficultyWorkFromTarget` = `2^256/(target+1)`),
  log-linear interpolated, provenance `flat | model | mark | market`. It stores the forward
  of the **difficulty** (the modelled martingale), NOT `E[target]`: the per-contract forward
  ratio is `F_R = E[D] / D_strike`, so no reciprocal-convexity adjustment is needed. A
  calibrator MUST therefore produce `E[D]`, not the arithmetic mean of observed targets. The
  `model` provenance is produced by rolling the chain's own retarget
  (`CalculateNextWorkRequired`) forward from the tip under a hashrate-drift assumption — the
  natural, no-external-data difficulty forward. Stored single-global per `PriceSource`.
- **`DifficultyVolSurface`** — chain-global `horizon_blocks → σ(log R)`, default-calibrated
  from realized log-difficulty variance off chain headers; over-rideable via a mark.

When neither is present the pricer degrades gracefully: missing curve → flat forecast
(tip `nBits`, today's behaviour) + a coverage warning; missing vol → `σ = 0` (deterministic
point forecast) + a warning that option time-value is unpriced.

### 9.5 Fixing already reached → deterministic (no forecast)

If `current_height ≥ fixing_height`, the underlying is **known**: the pricer reads
`nBits @ fixing_height` from the active chain (`GetAncestor(fixing_height)->nBits`, the same
value `OP_DIFFCFD_SETTLE` resolves) and prices the *exact* `ComputeDiffCfdPayout` outcome,
discounting only for the remaining time to `settle_lock_height`. It does **not** forecast a
resolved underlying. (Prior bug: the RPC passed only tip `nBits` and forecast a value that
was already fixed.)

### 9.6 Denomination & assets

IM and premium are **native TSC** (`difficulty_contract.{h,cpp}` rejects non-native IM, and
`premium` is a native-sat amount). So the valuation flow is **native-TSC PV first,
report-asset FX-conversion second** (mirrors `LegValuator`): compute MTM in atomic TSC,
discount on the native curve, then optionally `FXRate(TSC → report)` for portfolio
aggregation. Colored collateral and premium would be priced alongside the non-native asset
settlement extension (§8); there is no colored contract to mark today.
