# TensorCash Discussion Protocol V1

Semi-anonymous, proof-gated community discussion for model registration pre-alerts and challenge threads.

## Overview

Discussion posts are published as Nostr events and gated by BIP-322 proof-of-funds over native TSC UTXOs. This document specifies everything an external client needs to publish, verify, and display discussion posts without the Qt wallet.

## Nostr Event Format

| Field | Value |
|-------|-------|
| kind | `8322` (regular, append-only) |
| content | Message text (max 4096 chars) |
| pubkey | Author's Nostr public key (x-only, 64 hex) |

### Tags

| Tag | Values | Required |
|-----|--------|----------|
| `t` | `"tensorcash_discuss"` | Yes |
| `d` | `"<scope_type>:<scope_id>"` | Yes |
| `network` | Chain name (see below) | Yes |
| `proof` | JSON-serialized `OwnershipProof` | No (recommended) |

### Networks

Must match `ChainTypeToString()`:

`main`, `test`, `testnet4`, `signet`, `regtest`, `tensor`, `tensor-test`, `tensor-reg`

### Scope Types

V1 supports two scope types only:

| Scope Type | Scope ID | Use Case |
|-----------|----------|----------|
| `model_prealert` | `model_hash` (64 hex) | Pre-alert before model deposit |
| `model_challenge` | `challenge_block_hash` (64 hex) | Discussion around a model challenge |

The `d` tag value is `<scope_type>:<scope_id>`, e.g. `model_prealert:abcdef01...`.

## Proof-of-Funds Format

### Canonical Proof Message

```
TENSORCASH_DISCUSS:v1:<network>:<scope_type>:<scope_id>:<nostr_pubkey>:<expiry_height>
```

Fields:
- `network` — one of the valid chain names above
- `scope_type` — `model_prealert` or `model_challenge`
- `scope_id` — 64 hex characters (uint256 hash)
- `nostr_pubkey` — 64 hex characters (secp256k1 x-only pubkey of the post author)
- `expiry_height` — positive integer, block height after which the proof is invalid

Example:
```
TENSORCASH_DISCUSS:v1:tensor:model_prealert:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:50000
```

### OwnershipProof Object

Published in the `proof` Nostr tag as JSON:

```json
{
  "utxo_ref": "txid:vout",
  "address": "bitcoin_address",
  "message": "TENSORCASH_DISCUSS:v1:...",
  "signature": "bip322_signature_hex_or_base64",
  "asset_units": 1000000
}
```

- `utxo_ref` — `"<txid_hex>:<vout_int>"` referencing a confirmed UTXO
- `address` — the Bitcoin address controlling the UTXO
- `message` — the canonical proof message above
- `signature` — BIP-322 signature over `message` by `address`
- `asset_units` — native TSC amount in satoshis

## Verification Algorithm

Verifiers MUST apply all checks in order. A proof that fails any check is rejected.

### Step 1: Parse the message

Parse `TENSORCASH_DISCUSS:v1:<network>:<scope_type>:<scope_id>:<nostr_pubkey>:<expiry_height>`.

Reject if:
- Prefix is not `TENSORCASH_DISCUSS:v1:`
- Fewer or more than 5 colon-separated fields after prefix
- `network` is not a valid chain name
- `scope_type` is not `model_prealert` or `model_challenge`
- `scope_id` is not exactly 64 hex characters
- `nostr_pubkey` is not exactly 64 hex characters
- `expiry_height` is not a positive integer

### Step 2: Check network

Reject if `network` does not match the verifier's active chain (`getblockchaininfo` → `chain`).

### Step 3: Check scope binding

Reject if `scope_type` and `scope_id` from the proof message do not match the thread being viewed.

### Step 4: Check author binding

Reject if `nostr_pubkey` from the proof message does not match the Nostr event's `pubkey`.

### Step 5: Check expiry

Call `getblockcount` to get `current_height`.

Reject if `current_height >= expiry_height`.

### Step 6: Verify UTXO exists (confirmed only)

Call `gettxout <txid> <vout> false` (include_mempool = **false**).

Reject if:
- Result is null (UTXO doesn't exist or was spent)
- `confirmations` < 1

### Step 7: Verify UTXO value

For native TSC: read `value` field, convert to satoshis (`value * 1e8`).

Reject if `actual_sat < claimed_asset_units`.

### Step 8: Verify UTXO address

Extract `scriptPubKey.address` from the gettxout result.

Reject if it does not match the claimed `address`.

### Step 9: Verify bestblock chain binding

Extract `bestblock` from the gettxout result.

Call `getblockheader <bestblock>`.

Reject if the call fails (bestblock not in current chain — stale proof from a different chain/reorg).

### Step 10: Verify BIP-322 signature

Call `verifymessagebip322 <address> <signature> <message>`.

Reject if the result is not `true`.

### Result

If all 10 steps pass, the proof is **verified**. The verifier should display:
- `verified_units` — the actual UTXO value in satoshis
- `expiry_height` — when the proof expires

## Local Filtering (Client Policy)

Rate limiting and stake thresholds are **local client policy**, not protocol rules. Relays cannot enforce them. Recommended defaults:

| Filter | Default | Description |
|--------|---------|-------------|
| Min stake | 10,000 sat | Hide posts with verified_units below threshold |
| Hide expired | On | Hide posts where current_height >= expiry_height |
| Hide unverified | Off | Optionally hide posts without valid proofs |
| Per-proof rate limit | N/A | Max posts per proof per scope per hour (local filter) |

## Anonymity Properties

- The Nostr pubkey is a stable pseudonym (persisted at `~/.tensorcash/nostr_keys`), not linked to any on-chain identity
- The BIP-322 proof demonstrates UTXO ownership without revealing which Nostr pubkey belongs to which wallet
- The proof message binds the Nostr pubkey to the proof, preventing replay to a different author
- The proof does NOT prove the poster is the miner making the deposit — it only proves they hold TSC

## RPC Reference

### cosign.verify_discussion_proof

```
cosign.verify_discussion_proof <utxo_ref> <address> <message> <signature> <claimed_units>
```

Returns: `{ verified, error?, actual_units, bestblock, network?, scope_type?, scope_id?, nostr_pubkey?, expiry_height? }`

### cosign.discussion_post

```
cosign.discussion_post <scope_type> <scope_id> <content> [expiry_blocks=200] [min_stake=10000]
```

Creates a BIP-322 proof from the wallet, publishes via bridge to Nostr relays.

Returns: `{ event_id, scope_type, scope_id, content, created_at }`

### cosign.discussion_list

```
cosign.discussion_list <scope_type> <scope_id> [since=0] [limit=100]
```

Fetches posts from bridge, verifies each proof using the strict algorithm above.

Returns: `{ current_height, posts: [{ post_id, author_pubkey, content, created_at, has_proof, verified, rejected_reason?, verified_units?, expiry_height? }] }`
