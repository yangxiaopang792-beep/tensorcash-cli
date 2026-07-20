# TensorCash VDF-SPV Presync

TensorCash miners already embed a heavyweight proof blob to commit model work, but that blob alone leaves header-only sync vulnerable: an adversary can grind cheap short-hash headers and swamp presync peers without touching the expensive blob validation path. To close that gap we add a second, orthogonal proof dimension: a verifiable delay function (VDF) whose Wesolowski proof ties each header to wall-clock work. Light clients and presync peers request compact “sidecars” that expose the tick, VDF proof, and Merkle witnesses committed inside `hashPoW`. With those pieces they can reject fraudulent headers quickly, score chains by accumulated wall time, and avoid DoS traps while still accepting the same chain that full nodes validate.

## Protocol Surfaces & Sidecars

*Implementation*
- New p2p verbs `getheadext`/`headers_ext` advertise via `NODE_VDFSPV` (`src/protocol.h:130`, `src/init.cpp:986`). The sidecar wire struct matches `VdfExtSidecar` in net processing (`src/net_processing.cpp:792-858`).
- Miners and RPC helpers build Merkle branches so `hashPoW` commits to tick and VDF leaves (`src/primitives/proofblob.cpp:282-341`). Responses from `GETHEADERS_EXT` enforce the 1 KiB per-sidecar budget before sending (`src/net_processing.cpp:5572-5595`).
- Incoming sidecars are validated against local headers, Merkle branches, and activation gates; oversize payloads or missing proofs raise targeted eviction reasons (`src/net_processing.cpp:5624-5717`).

*Key tests*
- Unit: `src/test/headers_ext_branch_negative_tests.cpp`, `src/test/pow_blob_mismatch_tests.cpp`, `src/test/net_processing_vdf_eviction_tests.cpp`.
- Functional: `test/functional/p2p_vdf_spv_headers.py`, `test/functional/p2p_vdf_spv_rate_limits.py`.

## VDF Verification & Consensus Hooks

*Implementation*
- Header presync enqueues proofs for verification and deduplicates by `(prev_hash, proof_leaf)` to avoid redundant work (`src/net_processing.cpp:817-839`, `src/net_processing.cpp:1218-1240`).
- Verification reuses the in-tree Wesolowski verifier (`src/vdf/VdfGenerate.cpp:16-58`); results are cached with a 64 k entry cap and 10 minute TTL (`src/net_processing.cpp:1085-1117`).
- Consensus enforces both the Merkle commitment and the VDF proof once the network activates the feature (`src/validation.cpp:5343-5360`).

*Key tests*
- Unit: `src/test/vdf_verify_tests.cpp`, `src/test/vdf_roundtrip_tests.cpp`, `src/test/spv_sampling_quick_plumbing_tests.cpp`.
- Functional: `test/functional/p2p_vdf_spv_tip_preference.py` (hysteresis), `test/functional/p2p_vdf_spv_massive_tick_ban.py` (invalid proofs).

## Presync Scoring, Hysteresis, and Direct Fetch

*Implementation*
- Verified sidecars accumulate `cum_tick` per header and drive the hysteresis margin used before direct-fetching blocks (`src/net_processing.cpp:934-989`, `src/net_processing.cpp:3184-3248`).
- ASN corroboration gates deep reorgs so a single malicious source cannot trigger large fetches (`src/net_processing.cpp:1769-1800`, `src/net_processing.cpp:3235-3304`).
- Active-chain headers are pinned so subsequent prune cycles retain enough context to recompute hysteresis after long sleeps (`src/net_processing.cpp:1042-1082`).

*Key tests*
- Unit: `src/test/spv_hysteresis_tests.cpp`, `src/test/net_processing_vdf_eviction_tests.cpp`.
- Functional: `test/functional/p2p_vdf_spv_tip_preference.py`, `test/functional/p2p_vdf_spv_asn_corroboration.py`.

## DoS Hardening & Resource Caps

*Implementation*
- Per-peer HEADERS_EXT rates match legacy headers limits and the worker throttles VDF verifies to ~200 per second (`src/net_processing.cpp:836-843`, `src/net_processing.cpp:1145-1216`).
- Sidecar cache entries age out after 30 minutes unless the header remains on the active chain; global retention is capped at 60 k entries to prevent unbounded growth (`src/net_processing.cpp:820-826`, `src/net_processing.cpp:1042-1082`).
- Proof buckets, verification queues, and cache TTLs mirror the design doc to keep CPU and memory predictable even under adversarial input (`src/net_processing.cpp:817-840`, `src/net_processing.cpp:1085-1117`).

*Key tests*
- Unit: `src/test/net_processing_vdf_eviction_tests.cpp`, `src/test/proof_bucket_dedup_tests.cpp`, `src/test/ema_tick_tests.cpp`.
- Functional: `test/functional/p2p_vdf_spv_rate_limits.py`, `test/functional/p2p_vdf_spv_massive_tick_ban.py`.

## Interop & Tooling

*Implementation*
- RPC helpers repopulate `hashPoW` from the proof blob after tampering (`src/rpc/mining.cpp:144-1200`) so wallet/mempool flows remain coherent.
- `PopulateBlockPow` lets net processing graft retrieved proofs into a `CBlock` before validation paths touch consensus (`src/net_processing.cpp:4030-4056`).
- Service negotiation is automatic: nodes advertise `NODE_VDFSPV`, request sidecars opportunistically, and fall back to legacy behavior if peers do not support the extension (`src/net_processing.cpp:5359-5533`).

*Key tests*
- Functional: `test/functional/p2p_vdf_spv_headers.py`, `test/functional/p2p_vdf_spv_rate_limits.py`.
- Unit: `src/test/net_processing_headers_ext_smoke_tests.cpp`.

## Test Coverage Overview

| Feature | Unit Tests | Functional Tests | Fuzz |
| --- | --- | --- | --- |
| Sidecar encoding & Merkle commitments | `headers_ext_branch_negative_tests.cpp`, `pow_blob_mismatch_tests.cpp` | `p2p_vdf_spv_headers.py` | — |
| VDF verification & caching | `vdf_verify_tests.cpp`, `vdf_roundtrip_tests.cpp`, `net_processing_vdf_eviction_tests.cpp` | `p2p_vdf_spv_tip_preference.py`, `p2p_vdf_spv_rate_limits.py` | — |
| Presync scoring & hysteresis | `spv_hysteresis_tests.cpp`, `spv_sampling_quick_plumbing_tests.cpp` | `p2p_vdf_spv_tip_preference.py`, `p2p_vdf_spv_asn_corroboration.py` | — |
| DoS guards (rate limits, eviction) | `proof_bucket_dedup_tests.cpp`, `net_processing_vdf_eviction_tests.cpp` | `p2p_vdf_spv_rate_limits.py`, `p2p_vdf_spv_massive_tick_ban.py` | — |
| Consensus enforcement (hashPoW/VDF) | `pow_blob_mismatch_tests.cpp`, `validation_tests.cpp` | `p2p_vdf_spv_massive_tick_ban.py` | `test/fuzz/block_deserialize.cpp` (shared)

Recent CI runs (
`ninja test_bitcoin && test/functional/test_runner.py --jobs=4 p2p_vdf_spv_*`)
exercise the new suite end-to-end and keep the regression signal tight.

## Quick Usage Guide

1. **Negotiate capability** – Ensure your node advertises `NODE_VDFSPV` (default) and peers reciprocate. Non-supporting peers continue on legacy headers but won’t contribute to VDF scoring.
2. **Request sidecars** – During headers presync, net processing automatically batches `getheadext` queries over the same window as `getheaders`. Sidecars returning tick, VDF proof, and Merkle siblings must stay under 1 KiB.
3. **Verify proofs** – Verified sidecars transition headers to `VALID`, accumulate `cum_tick`, and feed the hysteresis gate. Proofs failing Merkle or VDF checks cause targeted `Misbehaving` reasons so peers are discouraged quickly.
4. **Score competing chains** – When multiple peers advertise competing tips, the presync logic compares cumulative tick (anchored to genesis/LCA) and applies hysteresis/backoff before fetching blocks.
5. **Monitor health** – Use functional tests or the unit harness to inspect cache sizes and eviction; `test_bitcoin --run_test=net_processing_vdf_eviction_tests` confirms the active chain remains pinned, while `p2p_vdf_spv_rate_limits.py` stress-tests rate limiting without affecting honest peers.
