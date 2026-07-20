# Post-Quantum Cryptography in TensorCash bcore (ML-DSA)

## Table of Contents

1. [Overview](#overview)
2. [ML-DSA Algorithm (FIPS 204)](#ml-dsa-algorithm-fips-204)
3. [Consensus Rules: Witness v2 Taproot](#consensus-rules-witness-v2-taproot)
4. [Address Format](#address-format)
5. [Wallet Integration](#wallet-integration)
6. [RPC Commands](#rpc-commands)
7. [PSBT Support](#psbt-support)
8. [Database Schema](#database-schema)
9. [Security Considerations](#security-considerations)
10. [Building with ML-DSA Support](#building-with-ml-dsa-support)
11. [Examples](#examples)
12. [Technical Reference](#technical-reference)

---

## Overview

TensorCash bcore implements **post-quantum signature support** using the **ML-DSA (Module-Lattice-Based Digital Signature Algorithm)** standardized in **FIPS 204**. ML-DSA provides quantum-resistant signatures that remain secure against attacks from large-scale quantum computers.

### Key Features

- **FIPS 204 ML-DSA**: NIST-standardized ML-DSA via `liboqs`
- **Witness v2 Taproot**: A witness version (v2) reserved for ML-DSA script-path-only spending
- **Wallet integration**: Key generation, storage, encryption, backup/restore
- **Three security levels**: ML-DSA-44, ML-DSA-65, ML-DSA-87 (NIST security levels 2, 3, 5)
- **Backward compatible**: Existing ECDSA/Schnorr transactions are unaffected
- **Bech32m addresses**: Native witness v2 addresses (witness-version character `z`)
- **PSBT support**: ML-DSA pubkey/signature/param-set fields for multi-party signing

### Why Post-Quantum Cryptography?

Large-scale quantum computers threaten ECDSA and Schnorr (Bitcoin's current signature schemes):

- **Shor's algorithm** can recover a private key from a public key in polynomial time on a quantum computer.
- **Harvest-now-decrypt-later**: an adversary can record exposed public keys today and forge spends once a quantum computer is available.
- **ML-DSA security** rests on module-lattice problems believed to be hard for both classical and quantum adversaries.

---

## ML-DSA Algorithm (FIPS 204)

### What is ML-DSA?

**ML-DSA** (Module-Lattice-Based Digital Signature Algorithm) is a quantum-resistant signature scheme based on the hardness of lattice problems, standardized by NIST in **FIPS 204**. It is the standardized form of CRYSTALS-Dilithium.

### Parameter Sets

ML-DSA offers three security levels, trading off security against signature size:

| Parameter Set | Security Level | Public Key | Secret Key | Signature Size |
|---------------|----------------|------------|------------|----------------|
| **ML-DSA-44** | NIST Level 2   | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| **ML-DSA-65** | NIST Level 3   | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| **ML-DSA-87** | NIST Level 5   | 2,592 bytes | 4,896 bytes | 4,627 bytes |

ML-DSA-65 is the default and provides roughly 192-bit security, comparable to AES-192.

### Implementation

ML-DSA primitives are provided by `liboqs`, registered as a submodule of this repository.

- Source: `src/mldsakey.h`, `src/mldsakey.cpp`
- The `CMLDSAKey` class (`src/mldsakey.h`) selects a parameter set via `mldsa::ParamSet` (`MLDSA_44` / `MLDSA_65` / `MLDSA_87`).
- **Script encoding of a public key**: `alg_id (0x01) || param_set (1 byte) || varint(pubkey_len) || pubkey` (`src/mldsakey.h`). The leading `alg_id = 0x01` identifies ML-DSA.

The secret key is held in an `mlock`-backed, zero-on-free container:

```cpp
// src/mldsakey.h
using MLDSASecretKey = std::vector<uint8_t, secure_allocator<uint8_t>>;
```

---

## Consensus Rules: Witness v2 Taproot

### Witness Version 2

ML-DSA spends use **witness version 2**, a Taproot variant whose output program is a 32-byte tweaked output key:

```
scriptPubKey: OP_2 <32-byte-program>
```

The 32-byte program size is enforced; the witness v2 branch only triggers for a non-P2SH program of exactly 32 bytes (`src/script/interpreter.cpp`).

### Script-Path Only (Key-Path Spending Disabled)

Witness v2 mirrors Taproot semantics, **except that key-path spending is disabled by consensus**. The branch is gated by the `SCRIPT_VERIFY_TAPROOT_SCRIPT_ONLY` flag. A witness stack that resolves to a single element (a key-path spend) is rejected:

```cpp
// src/script/interpreter.cpp — witness v2 branch
if (stack.size() == 1) {
    // Key-path spend is not permitted for v2 script-only Taproot
    return set_error(serror, SCRIPT_ERR_TAPROOT_KEYPATH_DISABLED);
}
```

**Reject code:** `SCRIPT_ERR_TAPROOT_KEYPATH_DISABLED` (`src/script/script_error.cpp`).

#### Why disable key-path spending?

1. **Quantum vulnerability**: Taproot key-path spends authenticate with a Schnorr signature over the internal/output key, which is quantum-vulnerable. Forcing script-path spends keeps the quantum-resistant ML-DSA leaf on the only spending path.
2. **No raw-pubkey footgun**: an ML-DSA public key is far larger than 32 bytes, so it can never be used directly as the v2 program. The 32-byte program must be a proper Taproot output key committing to an ML-DSA script leaf.

### Script-Path Spending

A witness v2 spend supplies a Taproot script-path proof:

```
Witness stack:
  - ML-DSA signature with trailing sighash byte
  - ML-DSA tapscript: <encoded_pubkey> OP_CHECKMLSIGVERIFY OP_TRUE
  - Control block: leaf_version||parity || internal_pubkey || merkle_path
```

The control block size, Taproot commitment, and tapleaf hash are validated exactly as for Taproot v1 (same `TAPROOT_CONTROL_*` size checks and `VerifyTaprootCommitment`). Mismatches yield `SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE` or `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH`. The leaf executes under `SigVersion::TAPSCRIPT`.

A valid scriptPubKey is constructed by committing the ML-DSA leaf into a Taproot tree:

```cpp
// ML-DSA script leaf
CScript tapscript;
tapscript << encoded_mldsa_pubkey << OP_CHECKMLSIGVERIFY << OP_TRUE;

// Build the Taproot tree and tweak the internal key
TaprootBuilder builder;
builder.Add(0, tapscript, TAPROOT_LEAF_TAPSCRIPT);
builder.Finalize(internal_key);
uint256 output_key = builder.GetOutput();

// 32-byte witness v2 program
CScript scriptPubKey = CScript() << OP_2 << ToByteVector(output_key);
```

### Standardness (Policy)

The policy layer permits witness v2 (script-only) spends and allows the larger stack items required for PQ signatures. ML-DSA opcodes are accepted **only** inside witness v2 tapscript leaves (`src/policy/policy.cpp`).

### Output Recognition (Solver)

The output script solver classifies the 32-byte `OP_2 <program>` output as `TxoutType::WITNESS_V2_TAPROOT` (string `"witness_v2_taproot"`), in `src/script/solver.cpp`.

---

## Address Format

### Bech32m Encoding

Witness v2 addresses are **bech32m** (BIP 350) with witness version 2. The data payload is prefixed with the value `2`, which maps to the bech32 character `z`:

```cpp
// src/key_io.cpp — WitnessV2Taproot encoder
std::vector<unsigned char> data = {2};
ConvertBits<8, 5, true>(...);
return bech32::Encode(bech32::Encoding::BECH32M, Bech32HRP(), data);
```

The human-readable prefix is the active network's HRP, followed by the v2 witness character `z`. On the TensorCash tensor chain the mainnet HRP is `tc` and the regtest HRP is `tcrt` (`src/kernel/chainparams.cpp`):

| Network | HRP    | Address prefix |
|---------|--------|----------------|
| Tensor mainnet | `tc`   | `tc1z…`        |
| Tensor regtest | `tcrt` | `tcrt1z…`      |

The witness-version characters are: v0 → `q`, v1 → `p`, v2 → `z`.

### Address Length

A witness v2 address encodes a 32-byte program: HRP + separator + 52 data characters + 6 checksum characters.

### Encoding / Decoding

```cpp
// Encoding
WitnessV2Taproot destination;  // 32-byte output key
std::string address = EncodeDestination(destination);

// Decoding
CTxDestination decoded = DecodeDestination(address);
if (std::holds_alternative<WitnessV2Taproot>(decoded)) {
    WitnessV2Taproot tap = std::get<WitnessV2Taproot>(decoded);
}
```

**Implementation**: `src/addresstype.h` (`WitnessV2Taproot`), `src/key_io.cpp`.

---

## Wallet Integration

### Key Generation

ML-DSA keys are generated with the `generatemldsaaddress` RPC. The RPC builds a single-leaf Taproot tree over the ML-DSA tapscript, derives the witness v2 output, and stores the key in the wallet database.

### Key Storage

ML-DSA keys are stored under dedicated wallet-database record types, indexed by `pk_hash` (the hash of the public key):

- `mlkey` — unencrypted ML-DSA key storage
- `cmlkey` — encrypted ML-DSA key storage
- `mlkeymeta` — ML-DSA key metadata (`CKeyMetadata`)

```cpp
// src/wallet/walletdb.cpp
DBKeys::MLDSA_KEY         || pk_hash → (key_data, checksum)
DBKeys::CRYPTED_MLDSA_KEY || pk_hash → encrypted key record
DBKeys::MLDSA_KEYMETA     || pk_hash → CKeyMetadata
```

**Implementation**: `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`.

### Wallet Encryption

ML-DSA secret keys are encrypted with the wallet master key, the same way ECDSA keys are. When the wallet is encrypted:

- **Unencrypted**: keys stored in plaintext under `mlkey`.
- **Encrypted**: secret keys encrypted and written under `cmlkey`; public keys remain in plaintext.
- **Locked**: master key not in memory; signing and decryption are unavailable.
- **Unlocked**: master key in memory; secret keys can be decrypted for signing.

When the wallet is encrypted, `generatemldsaaddress` requires the wallet to be unlocked (`walletpassphrase`); newly generated keys are encrypted immediately and written to `cmlkey`.

### Backup and Restore

ML-DSA keys are included in wallet backups (`backupwallet` / `restorewallet`). ML-DSA keys are **not** derived from an HD seed — each key is generated independently, so a wallet backup is the only recovery path. Losing the backup means permanent loss of the corresponding ML-DSA private keys.

---

## RPC Commands

### `generatemldsaaddress ( level )`

Generate a Taproot v2 ML-DSA address. Builds the single-leaf Taproot tree, stores the key in the wallet, and returns the address plus the construction material needed to spend.

**Parameter**:
- `level` (numeric, optional, default `65`): ML-DSA parameter set — `44`, `65`, or `87`. Any other value is rejected with `RPC_INVALID_PARAMETER`.

**Returns** (object):

| Field | Description |
|-------|-------------|
| `address` | Witness v2 address (bech32m) |
| `pubkey` | ML-DSA public key (raw FIPS 204, hex) |
| `seckey` | ML-DSA secret key (hex) |
| `level` | Parameter set (44/65/87) |
| `tapscript` | The tapscript spending condition |
| `scriptPubKey` | The scriptPubKey (witness v2 program) |
| `encoded_pubkey` | Script-encoded pubkey (alg_id, param_set, varint length, pubkey) |
| `internal_pubkey` | Wallet-owned Taproot internal key |
| `leaf_hash` | Tapleaf hash of the spending script |
| `merkle_root` | Merkle root (equals `leaf_hash` for a single-leaf tree) |
| `output_pubkey` | Tweaked output key in the scriptPubKey |
| `parity` | Parity bit of the output key (boolean), needed for the control block |
| `warning` | Note on the experimental nature of ML-DSA support |

**Implementation**: `src/wallet/rpc/pq.cpp` (`generatemldsaaddress`).

---

### `signmldsatransaction hexstring input_index seckey pubkey level tapscript prevout_value prevout_scriptpubkey internal_pubkey merkle_root parity`

Sign one transaction input with an explicitly supplied ML-DSA key and Taproot construction material.

**Parameters**:
1. `hexstring` (string): unsigned transaction hex
2. `input_index` (numeric): index of the input to sign
3. `seckey` (string): ML-DSA secret key (hex)
4. `pubkey` (string): ML-DSA public key (hex)
5. `level` (numeric): parameter set (44/65/87)
6. `tapscript` (string): tapscript hex containing `OP_CHECKMLSIGVERIFY OP_TRUE`
7. `prevout_value` (numeric): value of the previous output (in BTC)
8. `prevout_scriptpubkey` (string): scriptPubKey of the previous output (hex)
9. `internal_pubkey` (string): Taproot internal pubkey (from `generatemldsaaddress`)
10. `merkle_root` (string): merkle root (from `generatemldsaaddress`)
11. `parity` (boolean): parity bit (from `generatemldsaaddress`)

**Returns**: object containing the signed transaction hex.

**Implementation**: `src/wallet/rpc/pq.cpp` (`signmldsatransaction`).

---

### `signmldsatransactionwithwallet hexstring prevtxs`

Sign witness v2 ML-DSA inputs using ML-DSA keys already held by the wallet, given the relevant previous-output details. This is the convenience counterpart to `signmldsatransaction` — the wallet locates the matching key and the Taproot construction material rather than requiring them as arguments.

**Parameters**:
1. `hexstring` (string): unsigned transaction hex
2. `prevtxs` (array): objects with `txid`, `vout`, `scriptPubKey`, and `amount` for each ML-DSA input

**Implementation**: `src/wallet/rpc/pq.cpp` (`signmldsatransactionwithwallet`).

---

## PSBT Support

ML-DSA participates in Partially Signed Bitcoin Transactions (BIP 174) through three per-input field types (`src/psbt.h`):

| Field | Value | Contents |
|-------|-------|----------|
| `PSBT_IN_MLDSA_PUBKEY` | `0x1d` | ML-DSA public key for the input |
| `PSBT_IN_MLDSA_SIGNATURE` | `0x1e` | ML-DSA signature (with trailing sighash byte) |
| `PSBT_IN_MLDSA_PARAM_SET` | `0x1f` | Parameter set (44/65/87) |

These fields let multiple parties contribute and combine ML-DSA signatures for witness v2 inputs through the standard PSBT serialize/deserialize path.

---

## Database Schema

### ML-DSA Key Records

ML-DSA records use dedicated key prefixes so they do not collide with legacy ECDSA wallet validation:

| Record | Prefix | Key | Value |
|--------|--------|-----|-------|
| Unencrypted key | `mlkey` | `MLDSA_KEY \|\| pk_hash` | key data + checksum |
| Encrypted key | `cmlkey` | `CRYPTED_MLDSA_KEY \|\| pk_hash` | encrypted key record |
| Metadata | `mlkeymeta` | `MLDSA_KEYMETA \|\| pk_hash` | `CKeyMetadata` |

### Design Notes

1. **Separate from ECDSA keys**: dedicated record prefixes avoid conflicts with legacy wallet validation.
2. **Indexed by `pk_hash`**: the hash of the public key serves as the record index for efficient lookups.
3. **Metadata reuse**: ML-DSA metadata reuses the `CKeyMetadata` structure for consistency with ECDSA keys.

**Implementation**: `src/wallet/walletdb.cpp`.

---

## Security Considerations

### 1. Quantum Resistance

| Parameter Set | Approx. security | NIST category |
|---------------|------------------|---------------|
| ML-DSA-44 | ~128-bit (AES-128) | Level 2 |
| ML-DSA-65 | ~192-bit (AES-192) | Level 3 (default) |
| ML-DSA-87 | ~256-bit (AES-256) | Level 5 |

### 2. Key Management

- **No HD derivation**: ML-DSA keys are not derived from an HD seed; each is generated independently. Back up the wallet after generating keys.
- **Secret-key exposure**: `generatemldsaaddress` and `signmldsatransaction` accept and return raw secret keys for advanced workflows. Handle this material carefully; prefer `signmldsatransactionwithwallet` so the secret stays inside the wallet.
- **Key size**: ML-DSA secret keys are 2,560–4,896 bytes. In memory they live in an `mlock`-backed `secure_allocator` buffer that is zeroed on free.

### 3. Address Reuse

Generate a new ML-DSA address per receipt where practical, following normal best practice for output-key privacy and to limit the number of signatures produced under any single key.

### 4. Key-Path Footgun (Disabled by Consensus)

```
WRONG:   OP_2 <raw_mldsa_pubkey_hash>   → unspendable; key-path is disabled by consensus
CORRECT: OP_2 <taproot_output_key>      → spend with ML-DSA signature + tapscript + control block
```

Use `generatemldsaaddress` to construct addresses; manual construction requires careful Taproot tree building.

### 5. Signature Malleability

ML-DSA signatures are not malleable in the way unconstrained ECDSA encodings are: a third party cannot transform a valid signature into another valid signature for the same message and key.

### 6. Hybrid Security

This implementation uses **pure ML-DSA** (no combined ECDSA+ML-DSA witness). Spending authority on a witness v2 output rests entirely on the ML-DSA leaf.

---

## Building with ML-DSA Support

### Prerequisites

- `liboqs` (FIPS 204 ML-DSA support) — registered as a submodule of this repository
- A C++17 compiler
- CMake 3.16+

Initialize the `liboqs` submodule before building:

```bash
git submodule update --init --recursive
```

`liboqs` can alternatively be installed from the system package manager (for example `brew install liboqs` on macOS).

### Building

```bash
mkdir build && cd build
cmake -DENABLE_MLDSA=ON -DBUILD_WALLET=ON -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j"$(nproc)"
```

### CMake Options

- `ENABLE_MLDSA=ON` — enable ML-DSA support (requires `liboqs`)
- `BUILD_WALLET=ON` — enable wallet features (required for ML-DSA wallet integration)

---

## Examples

### Example 1: Generate an ML-DSA Address

```bash
# ML-DSA-65 (default)
bitcoin-cli generatemldsaaddress

# ML-DSA-87 (highest security)
bitcoin-cli generatemldsaaddress 87
```

Returns an object containing `address`, `pubkey`, `seckey`, `level`, `tapscript`, `scriptPubKey`, `encoded_pubkey`, `internal_pubkey`, `leaf_hash`, `merkle_root`, `output_pubkey`, and `parity`.

### Example 2: Fund an ML-DSA Address

```bash
bitcoin-cli sendtoaddress <mldsa_address> 1.0
bitcoin-cli generatetoaddress 1 <miner_address>
```

### Example 3: Spend from an ML-DSA Address (wallet-managed key)

```bash
RAW_TX=$(bitcoin-cli createrawtransaction \
  "[{\"txid\":\"$UTXO_TXID\",\"vout\":$UTXO_VOUT}]" \
  "{\"<destination_address>\":0.999}")

SIGNED_TX=$(bitcoin-cli signmldsatransactionwithwallet \
  "$RAW_TX" \
  "[{\"txid\":\"$UTXO_TXID\",\"vout\":$UTXO_VOUT,\"scriptPubKey\":\"$UTXO_SCRIPTPUBKEY\",\"amount\":$UTXO_AMOUNT}]")

bitcoin-cli sendrawtransaction $(echo "$SIGNED_TX" | jq -r '.hex')
```

To sign with an explicitly supplied key instead, use `signmldsatransaction` with the `seckey`/`pubkey`/`level`/`tapscript`/`internal_pubkey`/`merkle_root`/`parity` values returned by `generatemldsaaddress`.

### Example 4: Encrypt the Wallet

```bash
bitcoin-cli encryptwallet "my_secure_passphrase"
bitcoin-cli walletpassphrase "my_secure_passphrase" 60
# Newly generated ML-DSA keys are now stored encrypted (cmlkey)
bitcoin-cli generatemldsaaddress 65
```

### Example 5: Backup and Restore

```bash
bitcoin-cli backupwallet /secure/path/wallet_backup.dat
bitcoin-cli restorewallet "restored_wallet" /secure/path/wallet_backup.dat
bitcoin-cli loadwallet "restored_wallet"
```

---

## Technical Reference

### File Organization

**Core ML-DSA**:
- `src/mldsakey.h` / `src/mldsakey.cpp` — `CMLDSAKey`, key generation, signing, public-key encoding
- `src/script/interpreter.cpp` — `OP_CHECKMLSIG` / `OP_CHECKMLSIGVERIFY` execution, `SignatureHashMLDSA`, `CheckMLDSASignature`, witness v2 branch
- `src/addresstype.h` — `WitnessV2Taproot` destination type
- `src/key_io.cpp` — bech32m address encoding/decoding

**Consensus / policy**:
- `src/script/interpreter.cpp` — witness v2 validation, key-path disabled (`SCRIPT_ERR_TAPROOT_KEYPATH_DISABLED`), gated by `SCRIPT_VERIFY_TAPROOT_SCRIPT_ONLY`
- `src/policy/policy.cpp` — standardness for witness v2; ML-DSA opcodes restricted to witness v2 leaves
- `src/script/solver.cpp` — `TxoutType::WITNESS_V2_TAPROOT`

**Wallet**:
- `src/wallet/walletdb.h` / `src/wallet/walletdb.cpp` — database schema (with encryption)
- `src/wallet/rpc/pq.cpp` — `generatemldsaaddress`, `signmldsatransaction`, `signmldsatransactionwithwallet`
- `src/psbt.h` — ML-DSA PSBT field types (`0x1d`/`0x1e`/`0x1f`)

### Opcodes

| Opcode | Value | Behavior |
|--------|-------|----------|
| `OP_CHECKMLSIG` | `0xbb` | Verify an ML-DSA signature; push true/false |
| `OP_CHECKMLSIGVERIFY` | `0xbc` | Verify an ML-DSA signature; fail the script on mismatch |

(Defined in `src/script/script.h`.)

```cpp
// src/script/interpreter.cpp
case OP_CHECKMLSIG:
case OP_CHECKMLSIGVERIFY:
{
    // Stack: <sig_with_sighash_flag> <pk_blob>
    // The final byte of the signature element is the sighash type.
    uint8_t hash_type = sig_with_flag.back();
    if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83))) {
        // invalid sighash byte → encoding error
    }
    bool fSuccess = checker.CheckMLDSASignature(sig, pk_blob, hash_type,
                                                sigversion, execdata, serror);
    if (opcode == OP_CHECKMLSIGVERIFY) {
        if (!fSuccess) return set_error(serror, SCRIPT_ERR_MLDSA_VERIFY);
    } else {
        stack.push_back(fSuccess ? vchTrue : vchFalse);
    }
}
```

**Reject codes**: `SCRIPT_ERR_MLDSA_ENCODING` (malformed pubkey/signature element), `SCRIPT_ERR_MLDSA_VERIFY` (signature check failed under `OP_CHECKMLSIGVERIFY`). See `src/script/script_error.cpp`.

A typical ML-DSA leaf uses the VERIFY form:

```cpp
CScript tapscript;
tapscript << encoded_mldsa_pubkey << OP_CHECKMLSIGVERIFY << OP_TRUE;
```

### Sighash Computation

ML-DSA signatures sign a Taproot-style (BIP 341) message digest computed by `SignatureHashMLDSA` (`src/script/interpreter.cpp`). The sighash byte is the last byte of the signature witness element and must be one of:

| Sighash type | Value |
|--------------|-------|
| `SIGHASH_DEFAULT` | `0x00` (equivalent to `SIGHASH_ALL`) |
| `SIGHASH_ALL` | `0x01` |
| `SIGHASH_NONE` | `0x02` |
| `SIGHASH_SINGLE` | `0x03` |
| `SIGHASH_ALL \| ANYONECANPAY` | `0x81` |
| `SIGHASH_NONE \| ANYONECANPAY` | `0x82` |
| `SIGHASH_SINGLE \| ANYONECANPAY` | `0x83` |

The digest builder applies the same output/input masking as BIP 341: `SIGHASH_NONE` commits to no outputs, and `SIGHASH_SINGLE` commits to the output at the input's index. Any other byte is rejected with `SCRIPT_ERR_MLDSA_ENCODING`.

### Transaction Weight

Witness v2 ML-DSA spends carry substantially larger witnesses than ECDSA spends because the ML-DSA signature, the encoded public key, and the tapscript all live in the witness:

| Component | Size (ML-DSA-65) | Size (ECDSA) |
|-----------|------------------|--------------|
| Signature | ~3,309 bytes | ~71 bytes |
| Public key | ~1,952 bytes | ~33 bytes |
| Control block | 33 bytes | N/A |
| Tapscript | ~1,960 bytes | N/A |
| **Total witness** | **~7,250 bytes** | **~104 bytes** |

Witness bytes receive the standard SegWit discount (counted at 1 weight unit each rather than 4), but ML-DSA spends still cost considerably more in fees than ECDSA spends at the same fee rate.

### Memory Security

ML-DSA secret keys are held in `secure_allocator`-backed storage (`src/mldsakey.h`): memory is locked against paging to swap and zeroed on deallocation.

---

## References

### Standards

- **FIPS 204** — Module-Lattice-Based Digital Signature Standard — https://csrc.nist.gov/pubs/fips/204/final
- **BIP 341** — Taproot: SegWit version 1 spending rules — https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- **BIP 350** — Bech32m format for v1+ witness addresses — https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
- **BIP 174** — Partially Signed Bitcoin Transaction Format

### Libraries

- **liboqs** — Open Quantum Safe library (FIPS 204 implementation) — https://github.com/open-quantum-safe/liboqs

### Background

- **CRYSTALS-Dilithium** — https://pq-crystals.org/dilithium/
- **NIST Post-Quantum Cryptography** — https://csrc.nist.gov/projects/post-quantum-cryptography

---

## License

Distributed under the MIT License, consistent with Bitcoin Core.
