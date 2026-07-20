# TensorCash Model Registry System

This note documents the `bcore` model registration implementation: how model metadata is encoded, validated, persisted in the on-chain registry, and exposed through RPC tooling. It also collates the unit/functional coverage that guards each feature and finishes with a quick usage guide.

## High-Level Rationale

The TensorCash model registry provides a consensus-enforced mechanism for registering machine learning models on-chain. This enables the blockchain to:

1. **Maintain a canonical model database** that all nodes agree upon, queryable via RPC
2. **Delegate heavy ML verification** to an external Python/PyTorch-based API while keeping consensus rules in the core node lightweight
3. **Enable PoW based on registered models** by allowing blocks to reference models by identifier (`name@commit`) stored in the proof blob
4. **Prevent spam and abuse** through a bonding mechanism that requires collateral deposits

The registry is designed to be trustless: model validity is determined by an external validator (reachable over ZMQ), and the bonding cycle ensures that only models passing validation enter the registry with their collateral refunded, while failed models have their collateral burned.

## Two-Transaction Registration Protocol

*Implementation*

Model registration follows a deposit-commit protocol enforced through special transaction versions and OP_RETURN metadata encoding (`src/wallet/rpc/api_model_registration.h`, `src/wallet/rpc/api_model_registration.cpp`):

- **Deposit Transaction** (`tx.version == 5`, `MODEL_REGISTER_DEPOSIT_TX_VERSION`):
  - Locks consensus-configured collateral (`Consensus::Params::ModelRegistrationDeposit`, default 5 BTC) to a legacy P2PKH output owned by the registrant
  - Encodes metadata in multiple OP_RETURN outputs with tagged fields:
    - `MREG_NAME`: Model repository name (max 512 bytes, printable ASCII)
    - `MREG_COMMIT`: Model commit hash (max 256 bytes, printable ASCII)
    - `MREG_DIFF`: Difficulty multiplier (int64, must be positive)
    - `MREG_CID`: Optional IPFS CID (max 1280 bytes)
    - `MREG_OPT`: Optional extra metadata (max 4096 bytes)
    - `MREG_DEPOSIT`: SHA-256 hash of `name@commit` (model_hash, 32 bytes)
    - `MREG_OWNER`: Owner public key (33 or 65 bytes, must be valid and match P2PKH output)
  - Parser validates that model_hash matches `SHA256(name + '@' + commit)` and that exactly one P2PKH output ≥ collateral amount exists for the owner pubkey
  - Transaction is recognized during `ConnectBlock` (`src/validation.cpp:4071-4119`), creates `ModelRecord` with status `PendingDeposit`, and triggers external validation request if `g_ValidationApi` is available

- **Commit Transaction** (`tx.version == 6`, `MODEL_REGISTER_COMMIT_TX_VERSION`):
  - Must **not** spend the deposit UTXO; commits are funded by regular wallet inputs so the deposit stays locked until unlock logic releases or burns it later
  - **Success path** (`MREG_VERDICT_OK` tag present):
    - Echoes all metadata fields from deposit (name, commit, difficulty, optional CID/extra)
    - Encodes verdict/metadata in OP_RETURN outputs but otherwise behaves like an ordinary spend that can return change to wallet-controlled scripts
    - Consensus validates metadata match, enforces that the deposit remains untouched, and requires that the external validator returned `Model_OK`
    - Updates `ModelRecord` with the commit transaction details and increments the successful commit counter
  - **Failure path** (`MREG_VERDICT_FAIL` tag with model_hash + reason_code):
    - Uses the same funding model (no deposit input, change allowed); failure reason must match validator output but no burn output is required
    - Model remains pending/locked according to verification pipeline, and collateral is handled by later state transitions instead of at commit time
  - Processed during `ConnectBlock` (`src/validation.cpp:4122-4238`), looks up deposit via `g_modeldb->LookupModelByDeposit(prevout)`, validates state transition

*Helpers*
- Script construction: `CreateModelDepositScripts(metadata, owner_pubkey)`, `CreateModelCommitScriptsSuccess(metadata)`, `CreateModelCommitFailureScript(model_hash, reason_code)` (`src/wallet/rpc/api_model_registration.cpp:267-344`)
- Parsing: `ParseModelDepositTx(tx, payload, params)`, `ParseModelCommitTx(tx, payload)` (`src/wallet/rpc/api_model_registration.cpp:138-253`)
- Recognition: `IsModelDepositTx(tx, params)`, `IsModelCommitTx(tx)` (`src/wallet/rpc/api_model_registration.cpp:255-265`)
- Model hash derivation: `HashSHA256(model_name, model_commit)` produces canonical `uint256` identifier (`src/wallet/rpc/api_model_registration.cpp:124-136`)

*Key tests*
- Unit: `model_registration_sanity_tests.cpp` (`parse_deposit_success`, `parse_deposit_missing_owner_fails`, `parse_commit_success`, `parse_commit_failure`)
- Functional: `feature_model_reorg.py` (deposit/commit flow, reorg undo verification)

## ModelDB Persistence & Indexing

*Implementation*
- LevelDB-backed database under `<datadir>/modeldb/` using `CDBWrapper` (`src/modeldb.h`, `src/modeldb.cpp`)
- Two key-value spaces with distinct prefixes:
  - **Model records** (prefix `'m'`): `uint256 model_hash → ModelRecord`
    - `ModelRecord` captures: metadata (name, commit, difficulty, CID, extra), status (PendingDeposit/Registered/Locked), deposit details (txid, vout, amount, owner_key_hash, block_hash, block_height), commit details (txid, block_hash, block_height), verification code and details
    - Serialized using Bitcoin Core's `SERIALIZE_METHODS` macro for compact storage
  - **Deposit index** (prefix `'d'`): `COutPoint → uint256 model_hash`
    - Enables commit transactions to locate the model record by spending the deposit UTXO
    - Written on deposit confirmation, erased on commit confirmation
- Global instance `g_modeldb` constructed during `AppInitMain` after validation subsystem initialization (`src/init.cpp`)
- **Genesis seeding**: On first run (empty DB check), inserts default model from `Consensus::Params::{DefaultModelName, DefaultModelCommit, DefaultModelCID}` with status `Registered`, deposit/commit both pointing to genesis block, zero collateral (`src/modeldb.cpp:55-76`)
- **Duplicate prevention**: `WriteModel(..., overwrite=false)` rejects duplicate model_hash insertions; `ConnectBlock` checks `g_modeldb->Exists(model_hash)` and `block_deposits` local map to prevent same-block and cross-block duplicates (`src/validation.cpp:4084-4086`)

*Key methods*
- `WriteModel(model_hash, record, overwrite)`, `ReadModel(model_hash, record)`, `Exists(model_hash)`, `Erase(model_hash)` for record CRUD
- `WriteDepositIndex(outpoint, model_hash)`, `ReadDepositIndex(outpoint, model_hash)`, `EraseDepositIndex(outpoint)`, `LookupModelByDeposit(outpoint)` for index management
- `ForEachModel(callback)` for iteration (used by `getmodelslist` RPC)

*Key tests*
- Unit: `model_registration_sanity_tests.cpp` (deposit parsing implies DB writes during integration tests), `model_reorg_tests.cpp` (undo verification)
- Functional: `feature_model_reorg.py` (DB persistence across mine/reorg cycles)

## Consensus Integration & Validation

*Implementation*

Model registration transactions are consensus-critical and processed during `ConnectBlock` (`src/validation.cpp:4060-4238`):

1. **Deposit protection rule** (`src/validation.cpp:4060-4068`): Non-commit transactions (version ≠ 6) cannot spend deposit UTXOs. Any attempt triggers `bad-model-deposit-spend` consensus failure. This prevents accidental/malicious spending of pending deposits before commit.

2. **Deposit transaction processing** (`src/validation.cpp:4071-4119`):
   - Parse via `ParseModelDepositTx`; malformed transactions fail with `bad-model-deposit`
   - Check duplicate: `block_deposits` (local same-block map) and `g_modeldb->Exists(model_hash)` must both be false; violation triggers `duplicate-model-deposit`
   - Create `ModelRecord` with `PendingDeposit` status, capture deposit amount/outpoint/block details
   - Write to `g_modeldb` and index via `WriteDepositIndex` (only if `do_write == true`, i.e., not during reindex/test validation)
   - Trigger external validation: if `g_ValidationApi` exists and no cached result, send `Model` validation request with model metadata
   - Track in `block_deposits` for subsequent commit transaction lookup within same block

3. **Commit transaction processing** (`src/validation.cpp:4122-4238`):
   - Parse via `ParseModelCommitTx`; malformed transactions fail with `bad-model-commit`
   - Enforce single input rule: `tx.vin.size() == 1` or fail with `bad-commit-inputs`
   - Locate deposit record: check `block_deposits` map first (same-block commit), else `g_modeldb->LookupModelByDeposit(prevout)`; unknown deposit triggers `unknown-model-deposit`
   - Validate model_hash match between commit payload and deposit record (`bad-commit-model-hash`)
   - Validate record status is `PendingDeposit` (`bad-commit-status`)
   - **External validation check**: call `model_verification::VerifyModel(model_hash, metadata)` which checks basic sanity (name/commit non-empty, printable ASCII, difficulty > 0, size limits). On production networks with `g_ValidationApi`, the external service's verdict is authoritative; the commit transaction's success/failure tag must match the validation result (`bad-commit-verdict`)
   - **Success path validation**:
     - Metadata in commit must exactly match deposit metadata (`bad-commit-metadata`)
     - Deposit UTXO may not be referenced in `vin` (`commit-spends-deposit`)
     - External validator must acknowledge success before expiry; failure reason must be zero
     - Update `ModelRecord` to `Registered`, record commit txid/block, verification code/details
   - **Failure path validation**:
     - Reason code in commit must match validator's code (`bad-commit-reason`)
     - Deposit UTXO is still forbidden as an input, but change outputs paying the owner are allowed
     - Update `ModelRecord` to `Locked`, record commit details
   - Write updated record to `g_modeldb`, erase deposit index

4. **External Validation Pipeline** (`src/validationapi.h`, `src/validationapi.cpp`):
   - ZMQ PUSH/PULL channel to external validator (`VALIDATOR_HOST`, `VALIDATOR_PUSH_PORT`, `VALIDATOR_PULL_PORT` env vars)
   - Supports `Model` validation requests with model metadata payload
   - Receives `ValidationResponseValue`: `Model_OK` or `Model_Fail` (with reason code)
   - Tracks results in LevelDB `BlockValidationDB` and in-memory map
   - Periodically resends pending requests (capped retry attempts)
   - Mock implementation (`src/validationapi_mock.h`) for deterministic testing: allows setting responses via `validationmockset`, `validationmockdefault` RPCs

*Basic model verification* (`src/consensus/model_verification.cpp`):
- `VerifyModel(model_hash, metadata)` performs sanity checks enforced at consensus layer:
  - Name: 1-512 bytes, printable ASCII (space, newline, chars 32-126)
  - Commit: 1-256 bytes, printable ASCII
  - Difficulty: must be positive (> 0)
  - CID: ≤ 1280 bytes, printable ASCII
  - Extra: ≤ 4096 bytes, printable ASCII
- Returns `VerificationResult{passed, reason_code, details}` with codes:
  - `VERIFICATION_OK` (0): pass
  - `VERIFICATION_ERR_EMPTY_NAME` (1)
  - `VERIFICATION_ERR_EMPTY_COMMIT` (2)
  - `VERIFICATION_ERR_NONPOSITIVE_DIFFICULTY` (3)
  - `VERIFICATION_ERR_METADATA_TOO_LARGE` (4)
- Note: This is a lightweight check; production networks delegate heavy ML model validation (architecture, weights integrity, performance benchmarks) to the external Python/PyTorch API

*Key tests*
- Unit: `model_validation_tests.cpp` (`unregistered_model_rejected_on_tensorreg`, `default_model_accepted_on_tensorreg`, `tensormain_rejects_without_api`), `difficulty_mixed_models_tests.cpp`
- Functional: `feature_model_reorg.py` (Model validation request capture, mock defaults)

## Anti-DoS Properties

The model registration system includes several anti-spam and anti-abuse mechanisms:

1. **Collateral bonding** (`Consensus::Params::ModelRegistrationDeposit`, default 5 BTC):
   - Deposit transaction locks significant capital in a P2PKH output
   - Failed models have collateral burned (all outputs OP_RETURN in commit)
   - Successful models receive collateral refund (minus fees)
   - Economic disincentive against registering junk/malicious models

2. **Duplicate prevention**:
   - `model_hash = SHA256(name + '@' + commit)` provides canonical identity
   - Consensus rejects duplicate model_hash in same block (`block_deposits` map check) or across blocks (`g_modeldb->Exists()`)
   - Prevents registry pollution and ensures one canonical record per model identifier

3. **Metadata size limits** (enforced in `model_verification::VerifyModel`):
   - Name: 512 bytes max
   - Commit: 256 bytes max
   - CID: 1280 bytes max (generous IPFS allowance)
   - Extra: 4096 bytes max
   - Prevents blockchain bloat from oversized OP_RETURN payloads

4. **Deposit spending protection**:
   - Only commit transactions (version 6) can spend deposit UTXOs
   - Regular transactions attempting to spend deposits fail consensus (`bad-model-deposit-spend`)
   - Ensures deposits can only be resolved through proper commit flow

5. **Single-input commit constraint**:
   - Commit transactions must spend exactly one deposit UTXO
   - Prevents batch-commit exploits and simplifies state tracking

6. **ASCII printability requirement**:
   - All metadata fields must contain printable ASCII (space, newline, 32-126)
   - Prevents binary garbage, control characters, potential parsing exploits

## Bonding Cycle & State Machine

Model registration follows a strict state machine enforced at consensus:

```
                    ┌─────────────────┐
                    │   (No Record)   │
                    └────────┬────────┘
                             │
                      Deposit TX (v5)
                      Locks collateral
                             │
                             ▼
                    ┌─────────────────┐
                    │ PendingDeposit  │◄──┐
                    └────────┬────────┘   │
                             │            │
                    External Validation   │
                      (Model Request)     │
                             │            │
                             ▼            │
              ┌──────────────┴───────────────┐
              │                              │
        Model_OK                        Model_Fail
              │                              │
              ▼                              ▼
     Commit TX (v6, Success)        Commit TX (v6, Failure)
     Refunds collateral              Burns collateral
              │                              │
              ▼                              ▼
     ┌──────────────┐              ┌──────────────┐
     │  Registered  │              │    Locked    │
     └──────────────┘              └──────────────┘
          (Final)                       (Final)
              ▲                              ▲
              │                              │
              └────────── Reorg ─────────────┘
                    (DisconnectBlock)
                    Reverts to PendingDeposit
```

State transitions:
- **None → PendingDeposit**: Deposit transaction confirms, collateral locked, external validation triggered
- **PendingDeposit → Registered**: Commit (success) confirms, collateral refunded, model available for use
- **PendingDeposit → Locked**: Commit (failure) confirms, collateral burned, model unusable
- **Registered/Locked → PendingDeposit**: Block reorg via `DisconnectBlock`, reverts commit, restores deposit index
- **PendingDeposit → None**: Block reorg disconnects deposit block, erases record entirely

Maturity requirement:
- Models registered at height H become available for PoW at height H + 100 (100-block maturity, similar to coinbase)
- Prevents chain instability from rapidly changing model sets during shallow reorgs

## Reorg Handling & Undo

*Implementation*

`DisconnectBlock` (`src/validation.cpp:2725-2785`) properly reverses model registration state:

1. **Revert commits first** (reverse iteration `block.vtx.rbegin()` → `rend()`):
   - Parse commit transactions, extract model_hash
   - Read `ModelRecord` from `g_modeldb`, verify `record.commit_txid == tx.GetHash()`
   - Revert to `PendingDeposit`: set `status = PendingDeposit`, clear commit_txid/block_hash/height, clear verification code/details
   - Restore deposit index: `WriteDepositIndex(deposit_outpoint, model_hash)`

2. **Erase deposits** (forward iteration):
   - Parse deposit transactions
   - Read `ModelRecord`, verify `record.deposit_txid == tx.GetHash()`
   - Erase record: `g_modeldb->Erase(model_hash)`
   - Erase deposit index: `EraseDepositIndex(deposit_outpoint)`

Order matters: commits must be reverted before deposits to preserve deposit index integrity during same-block reorgs. This ensures clean rollback even if deposit and commit occur in the same disconnected block.

*Key tests*
- Unit: `model_reorg_tests.cpp` (simulates ConnectBlock/DisconnectBlock cycles)
- Functional: `feature_model_reorg.py` (mine deposit+commit, invalidate block, verify model erased, reconsider block, verify model restored)

## RPC Surface

### Query & Inspection

- **`getmodelslist [short_view=true]`** (`src/rpc/custom.cpp:97-170`):
  - Returns array of all registered models from `g_modeldb`
  - Short view (default): `{model_hash, model_name, model_commit, difficulty, status}`
  - Extended view (`short_view=false`): adds `{cid, extra, deposit_txid, deposit_vout, deposit_amount, owner_key_hash, deposit_block_hash, deposit_block_height, commit_txid, commit_block_hash, commit_block_height, verification_code, verification_details}`
  - Status values: 0 = PendingDeposit, 1 = PendingVerification, 2 = Registered, 3 = Locked, 4 = Banned
  - Example: `bitcoin-cli getmodelslist false`

- **`getmodelinfo "model_hash"`** (`src/rpc/custom.cpp:172-201`):
  - Looks up single model by hex-encoded model_hash
  - Returns full ModelRecord JSON (all metadata/deposit/commit/burn/verification/challenge fields) or `"No model found"`
  - Example: `bitcoin-cli getmodelinfo a1b2c3...`

### Construction Helpers (Wallet RPCs)

- **`createmodeldeposit "name" "commit" difficulty ["cid"] ["extra"]`** (`src/wallet/rpc/transactions.cpp:1081-1115`):
  - Constructs deposit transaction (version 5) with OP_RETURN metadata and collateral P2PKH output
  - Funds from wallet, signs, optionally broadcasts
  - Returns: `{txid, model_hash, deposit_vout, hex}`
  - Requires wallet with sufficient funds (≥ 5 BTC + fees)

- **`createmodelcommit "deposit_txid" deposit_vout [success=true] [reason_code=0]`** (`src/wallet/rpc/transactions.cpp:1157-1267`):
  - Constructs commit transaction (version 6) spending deposit UTXO
  - Success path: refunds collateral to owner, echoes metadata with `MREG_VERDICT_OK`
  - Failure path: burns collateral, emits `MREG_VERDICT_FAIL` with reason_code
  - Requires wallet to own the deposit UTXO (private key for owner pubkey)
  - Returns: `{txid, hex}`

### Mock Validation API (Testing Only)

Enabled via `-validationapi=mock`, allows deterministic control of validation responses:

- **`validationmockset "id" "type" "value"`** (`src/rpc/custom.cpp:266-288`):
  - Sets mock response for specific model_hash or block_hash
  - Type: `model` | `quick` | `full`
  - Value (for model): `model_ok` | `ok` | `model_fail` | `fail`
  - Example: `bitcoin-cli validationmockset a1b2c3... model model_ok`

- **`validationmockdefault "type" "value"`** (`src/rpc/custom.cpp:290-310`):
  - Sets default response for all unspecified IDs of given type
  - Example: `bitcoin-cli validationmockdefault model model_ok`

- **`validationmockclear ["id"] ["type"]`** (`src/rpc/custom.cpp:312-340`):
  - Clears mock responses (all, or specific id/type)
  - Example: `bitcoin-cli validationmockclear a1b2c3... model`

- **`validationmockrequests`** (`src/rpc/custom.cpp:343-368`):
  - Returns captured validation requests (for test assertions)
  - Example: `bitcoin-cli validationmockrequests`

*Key tests*
- Functional: `feature_model_reorg.py` (uses mock RPCs to set Model_OK default, capture requests)

## Test Coverage Overview

| Feature | Unit Tests | Functional Tests |
| --- | --- | --- |
| Transaction parsing & script construction | `model_registration_sanity_tests.cpp` (`parse_deposit_success`, `parse_deposit_missing_owner_fails`, `parse_commit_success`, `parse_commit_failure`) | – |
| ModelDB persistence & indexing | `model_reorg_tests.cpp` (simulated ConnectBlock/DisconnectBlock CRUD) | `feature_model_reorg.py` (RPC-driven DB verification) |
| Consensus validation & state machine | `model_validation_tests.cpp` (`unregistered_model_rejected_on_tensorreg`, `default_model_accepted_on_tensorreg`, `tensormain_rejects_without_api`) | `feature_model_reorg.py` (deposit/commit flow, duplicate prevention) |
| Basic model verification | `model_validation_tests.cpp` (verification code paths), `consensus/model_verification.cpp` unit coverage via validation tests | – |
| Difficulty & mixed-model scenarios | `difficulty_mixed_models_tests.cpp` | – |
| Reorg undo | `model_reorg_tests.cpp` (unit-level DisconnectBlock verification) | `feature_model_reorg.py` (invalidate/reconsider blocks, verify state rollback) |
| RPC surface | – | `feature_model_reorg.py` (`createmodeldeposit`, `createmodelcommit`, `getmodelslist`, `getmodelinfo`, mock validation RPCs) |

All tests pass in CI. The functional test `feature_model_reorg.py` is isolated, single-node, parallel-safe, and covers the complete registration flow including mock validation API interaction.

## High-Level Usage Guide

1. **Configure external validator** (production deployments):
   - Set environment variables: `VALIDATOR_HOST`, `VALIDATOR_PUSH_PORT`, `VALIDATOR_PULL_PORT`
   - Run external Python/PyTorch validation service listening on specified ZMQ sockets
   - Service receives model metadata (name, commit, difficulty, CID, extra) and responds with `Model_OK` or `Model_Fail` + reason_code
   - See `src/validationapi.h` for protocol details

2. **Register a model** (as end user):
   - Ensure wallet has ≥ 5 BTC (or `Consensus::Params::ModelRegistrationDeposit` for your chain)
   - Call `createmodeldeposit "repo/model" "commit_hash" 1000000 "QmIPFS..." "metadata"`
     - Returns `{txid, model_hash, deposit_vout}`
   - Mine/wait for confirmation (deposit transaction enters ModelDB with status `PendingDeposit`)
   - External validator processes model (async)
   - If validation passes: call `createmodelcommit deposit_txid deposit_vout true`
     - Refunds collateral minus fees, model becomes `Registered`
   - If validation fails: call `createmodelcommit deposit_txid deposit_vout false reason_code`
     - Burns collateral, model becomes `Locked`
   - Mine/wait for commit confirmation

3. **Query registered models**:
   - List all: `bitcoin-cli getmodelslist` (short) or `bitcoin-cli getmodelslist false` (detailed)
   - Lookup specific: `bitcoin-cli getmodelinfo <model_hash>`
   - Filter by status: iterate results, check `status` field (0=Pending, 1=Registered, 2=Locked)

4. **Use registered models for PoW**:
   - Registered models (status = 1) become available 100 blocks after commit
   - Mining code references model by identifier: `name@commit` stored in `block.pow.model_identifier`
   - Consensus validates model_hash exists in `g_modeldb` and has `Registered` status
   - Difficulty adjustment uses `metadata.difficulty` and `Consensus::Params::ModelDifficultyNormalizer` to compute `nAdjBits`
   - External miner (via `ExtAPI`, ZMQ) performs actual PoW computation using model

5. **Test with mock validator** (development/CI):
   - Start node with `-validationapi=mock`
   - Set defaults: `bitcoin-cli validationmockdefault model model_ok`
   - Register model as above; commit will succeed deterministically
   - Inspect requests: `bitcoin-cli validationmockrequests`
   - See `test/functional/feature_model_reorg.py` for complete example

## Security Considerations

- **External validator trust**: Production deployments should implement authentication/integrity for ZMQ channels (e.g., TLS, HMAC). Current implementation does not enforce cryptographic channel security; operators must secure the communication path between core node and validator service.

- **Model identifier collisions**: SHA-256 hash of `name@commit` provides 256-bit collision resistance. Attacker cannot feasibly create duplicate model_hash to exploit registry.

- **Collateral bond sizing**: Default 5 BTC deposit is configurable via `Consensus::Params::ModelRegistrationDeposit`. Adjust based on token economics and desired spam resistance.

- **Metadata injection attacks**: All metadata fields enforce printable ASCII and size limits. Parser rejects binary payloads, control characters, oversize data. OP_RETURN outputs are provably unspendable (no script execution risk).

- **Reorg attack surface**: Model registry state correctly reverts during reorgs via `DisconnectBlock` undo. 100-block maturity requirement prevents shallow-reorg manipulation of active model set.

- **Sybil resistance**: One deposit UTXO → one commit transaction → one model record. Multi-model registration requires separate deposits (linear cost scaling).
