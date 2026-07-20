TensorCash bcore: Initial Summary of Changes vs. Bitcoin Core

This document describes the main functional changes introduced in this repository compared to upstream Bitcoin Core. It is based on reading the code present in this repository, not on a clean diff to an upstream tag. Names and file paths below are from this tree.

Scope note: This file focuses on the forked core changes in `src/`.

High-level Themes
- Externalized mining: Blocks are mined via an external service over ZeroMQ, not by local nonce scanning.
- External validation: Block and model validations can be delegated to an external validator over ZeroMQ.
- Model registry on-chain: Special transactions register models; accepted registrations populate a LevelDB-backed model database, queryable via custom RPCs.
- Block header and consensus extensions: Additional header fields and a proof blob are introduced; JSON RPCs expose extra fields.

Consensus and Block Format
- CBlockHeader additions (see `src/primitives/block.h`):
  - `nAdjBits` (uint32): Adjusted bits (separate from `nBits`).
  - `hashPoW` (uint256): Hash of proof-of-work blob.
  - `flags` (uint8).
  - Serialization order updated to include `nAdjBits`, `hashPoW`, `flags` (breaking change vs upstream wire/disk format).
- CBlock additions:
  - `CProofBlob pow;` (see `src/primitives/proofblob.h`) stores extra proof data, including:
    - Model metadata: `model_identifier` (format `name@commit`), `ipfs_cid`, `compute_precision`, various sampling parameters, logits and stats.
    - Methods: `GetModelHash()` (SHA-256 of `name@commit`), `GetHash()` for the blob.
  - `uint64_t cumulative_tick;`, extra cache flags.
- pow/target changes (`src/pow.cpp`):
  - Debug logging added. Difficulty retarget logic stays similar; PoW check still compares `hash` against target derived from `nBits`.
  - Note: Header serialization includes `nAdjBits`, but PoW target derivation uses `nBits`.

External Mining Pipeline
- New `node::ExtAPI` (`src/node/extapi.*`):
  - ZMQ PUSH to miner (`MINER_HOST`, `MINER_PUSH_PORT`), ZMQ PULL bound locally (`MINER_PULL_BIND`, `MINER_PULL_PORT`).
  - Sends compact block header requests with request IDs; receives `MiningResponse` (FlatBuffers) with `nonce`, `adjusted_bits`, `pow_blob_hash`, and blob payload.
  - Populates `CBlock` fields (`nNonce`, `nAdjBits`, `pow` blob, `hashPoW`).
  - Rate limiting, simple health checks, metrics, and reconnection logic included.
- Integration points:
  - Mining RPC flow (`src/rpc/mining.cpp`): The traditional nonce-scan loop is commented out and replaced with calls to `ExtAPI::SendApiRequest` and `GetApiAnswer`.
  - `NodeContext` holds `std::unique_ptr<ExtAPI> expt_api;` constructed during init.

External Validation Pipeline
- New `ValidationAPI` (`src/validationapi.*`):
  - ZMQ PUSH/PULL channel defined by `VALIDATOR_HOST`, `VALIDATOR_PUSH_PORT`, `VALIDATOR_PULL_PORT` env via `EnvConfig` (`src/apicomponents.h`).
  - Supports four request types: `Quick`, `Quick_Smell`, `Full`, `Model`.
  - Tracks results in a LevelDB `BlockValidationDB` and in-memory map for models.
  - Receives responses and, for Full validations, can accept the validated block via `ChainstateManager::AcceptBlock`.
  - Periodically resends requests with capped retry attempts.
- Consensus hook for model validation (`src/validation.cpp`):
  - During `ConnectBlock`, scans transactions for model registrations (see below). For each registration:
    - Computes `model_hash = HashSHA256(name, commit)`.
    - Sends a `ValidationAPI` Model request if needed; waits or polls result.
    - On `Model_OK`, inserts record into ModelDB; duplicate registrations or failed validations cause block connection failure.

Model Registry
- Two-transaction protocol (`src/wallet/rpc/api_model_registration.*`):
  - Deposit transaction (`MODEL_REGISTER_DEPOSIT_TX_VERSION`):
    - Locks consensus-configured collateral to a legacy P2PKH output owned by the caller.
    - OP_RETURN tags include metadata (`MREG_NAME`, `MREG_COMMIT`, `MREG_DIFF`, optional `MREG_CID`, `MREG_OPT`), plus `MREG_DEPOSIT` (model hash) and `MREG_OWNER` (owner pubkey).
  - Commit transaction (`MODEL_REGISTER_COMMIT_TX_VERSION`):
    - Success path: refunds collateral to owner and appends metadata + `MREG_VERDICT_OK` tag.
    - Failure path: burns collateral and emits `MREG_VERDICT_FAIL` with model hash + reason code.
  - Helpers:
    - `CreateModelDepositScripts(...)`, `CreateModelCommitScriptsSuccess(...)`, `CreateModelCommitFailureScript(...)` for construction.
    - `ParseModelDepositTx(...)`, `ParseModelCommitTx(...)`, `IsModelDepositTx(...)`, `IsModelCommitTx(...)` for recognition.
    - `HashSHA256(metadata)` to compute canonical model hash from metadata.
- ModelDB (`src/modeldb.*`):
  - LevelDB-backed key-value store under `<datadir>/modeldb_v2`.
  - Keys: model hashes (`uint256`). Values: `ModelRecord` capturing metadata, deposit details (txid, vout, amount, owner hash, deposit block), commit details (txid, block), and verification metadata.
  - Seeded on first run with a default model from `Consensus::Params::{DefaultModelName, DefaultModelCommit, DefaultModelCID}` pointing to genesis.
  - Global instance `g_modeldb` constructed during init.

Custom RPC Methods (`src/rpc/custom.cpp`)
- `startmining "address"` → Starts external mining threads and sets coinbase output script to the provided address via `ExtAPI::StartMining`.
- `stopmining` → Stops external mining threads.
- `getmodelslist (short_view=true)` → Returns array of model records:
  - Short view: `{ model_hash, model_name, model_commit, difficulty }`.
-  - Extended view: adds `{ cid, extra, deposit_txid, deposit_block_hash, commit_txid, commit_block_hash, verification details }`.
- `getmodelinfo "model_hash"` → Returns full ModelRecord JSON object or "No model found".
- `sayhello` → Test stub.

RPC Output Extensions
- `getblockheader`/`getblock` JSON include new fields (see `src/rpc/blockchain.cpp`):
  - `shortHash` (short-derived hash), `adjBits`, `hashPoW`.
  - `getblock` also includes `tst` which echoes `block.pow.model_identifier`.

Init/Startup Changes (`src/init.cpp`)
- `NodeContext` now constructs `node.expt_api` (ExtAPI) in `InitContext`.
- During chainstate load, constructs and initializes `g_ValidationApi`.
- During `AppInitMain`, constructs `g_modeldb` after validation signals are set up.

Environment and Config (`src/apicomponents.h`)
- `EnvConfig::fromEnvironment(prefix, defaultPush, defaultPull)` reads:
  - `<PREFIX>_HOST`, `<PREFIX>_PUSH_PORT`, `<PREFIX>_PULL_BIND`, `<PREFIX>_PULL_PORT`.
  - Prefixes used:
    - `MINER_*` for external miner (ExtAPI)
    - `VALIDATOR_*` for validator (ValidationAPI)
- Built-in `RateLimiter` for simple per-minute request limiting on inbound solutions.

CLI Support (`src/rpc/client.cpp`)
- Adds argument conversion entries for `getmodelslist`, `createmodeldeposit`, and `createmodelcommit` (client-side), so `bitcoin-cli` can call new RPCs conveniently.

Compatibility and Implications
- Block header serialization and content changes break compatibility with unmodified Bitcoin Core peers and tools.
- Mining and some validity decisions depend on external services reachable over ZMQ. Nodes without configured external miner/validator are expected to be unable to mine and may reject or stall on model registration blocks.
- The model registry introduces a new consensus rule: blocks containing duplicate model registrations or registrations not approved by the external validator fail `ConnectBlock`.
- RPC surface area is extended with a “custom” command set and existing blockchain RPCs include additional fields; downstream tools may need updates.

Open Questions / To Verify
- Security model for the external validator response (trust/attestation) is not visible here; production deployments should define authentication/integrity for ZMQ channels.

Pointers to Notable Files
- External miner bridge: `src/node/extapi.h`, `src/node/extapi.cpp`, hooks in `src/rpc/mining.cpp`.
- External validator: `src/validationapi.h`, `src/validationapi.cpp`, `src/validation.cpp` integration.
- Model registry: `src/wallet/rpc/api_model_registration.*`, `src/modeldb.*`.
- Custom RPCs: `src/rpc/custom.cpp`.
- Proof blob and header: `src/primitives/proofblob.h`, `src/primitives/block.h`.
- Consensus params extended: `src/consensus/params.h` (default model fields).
