# TensorCash CLI and Windows wallet source

This repository contains the complete source code used to build the TensorCash
node and wallet applications. It is intended for community review,
reproducible builds, and developer collaboration.

Prebuilt Linux x86_64 binaries are available from the
[v29.99.0 release](https://github.com/kinger2023/tensorcash-cli/releases/tag/v29.99.0).

Windows 10/11 x64 users can build both the installable Qt GUI wallet and the
command-line tools with the **Build Windows wallet** GitHub Actions workflow.
See [WINDOWS_BUILD_CN.md](WINDOWS_BUILD_CN.md) for build and configuration
instructions.

Source origin: [tensorcash/bcore](https://github.com/tensorcash/bcore).

---

# bcore — TensorCash consensus node

`bcore` is the TensorCash full node: a consensus engine derived from Bitcoin
Core and extended with the rules that define the TensorCash layer-1 network. It
is the source of truth for consensus and is consumed by the umbrella
[`tensorcash`](https://github.com/tensorcash/tensorcash) repository as a
submodule.

## What TensorCash adds on top of the base node

- **Proof-of-inference PoW and a VDF timing layer.** Mining commits real model
  inference work, and a Wesolowski verifiable-delay-function proof ties each
  header to wall-clock time. A model-verification path (`src/consensus/model_verification.cpp`,
  `src/crypto`/`src/vdf` helpers) checks that work; see `model-readme.md`.

- **VDF-SPV presync.** Light clients and presync peers fetch compact header
  sidecars (the `getheadext`/`headers_ext` p2p verbs, advertised via
  `NODE_VDFSPV`) carrying the tick, VDF proof, and Merkle witnesses committed
  inside `hashPoW`, so they can reject ground headers and score chains by
  accumulated wall time without full block validation. See `spv-readme.md`.

- **Native assets with a TLV wire format.** Outputs carry optional TLV bytes
  (`vExt`, gated by transaction flag `0x02`) that txid/wtxid and the Taproot /
  BIP143 sighashes commit to. The TLV catalogue (`src/assets/asset.h`) includes
  the asset tag (`0x01`), issuer registration (`0x10`), the issuer scalar feed
  (`0x11`), ZK parameter and proof payloads (`0x20`, `0x22`), and the ICU
  acceptance record (`0x40`, `src/assets/icu_acceptance_record.h`). See
  `asset-readme.md`, `ICU_ACCEPTANCE_RECORD.md`, and `ICU_CHILD.md` for the
  on-chain registry, issuer registration, and sponsored-child assets.

- **ZK / KYC enforcement in consensus.** Asset spends can require a Groth16
  compliance proof transported in the `ZK_PROOF_PAYLOAD` (`0x22`) TLV. The proof
  is verified during transaction validation
  (`groth16::VerifyGroth16WithPolicy`, `src/crypto/groth16.cpp`, called from
  `src/consensus/tx_verify.cpp`), with consensus reject codes including
  `zk-proof-bad`, `zk-epoch-stale`, and `kyc-proof-not-hdv1`.

- **On-chain settlement primitives.** A native difficulty contract-for-difference
  (`OP_NBITS_AT`/`OP_DIFFCFD_SETTLE`) and a generalised issuer-published-scalar
  settlement opcode (`OP_SCALAR_CFD_SETTLE`) settle covenant outputs against
  published feeds, with tokenised difficulty-option series built on top. See
  `DIFFICULTY_DERIVATIVE.md`, `CFD_GENERALISATION.md`, `OPTION_TOKENIZATION.md`,
  and `OPTION_SERIES_FREEZE.md`.

- **Post-quantum spending.** Witness-v2 outputs spend under ML-DSA (FIPS 204)
  signatures (`src/crypto/mldsaverify.cpp`), with `generatemldsaaddress` and
  `signmldsatransaction` wallet RPCs. See `PQ-README.md`.

`README-CHANGES.md` summarises the departures from the upstream base node.

## Building

See [`INSTALL.md`](INSTALL.md) and the platform build guides under
[`doc/`](doc/) (`doc/build-unix.md`, `doc/build-osx.md`,
`doc/build-windows.md`). `bcore` depends on the TensorCash shared utilities
(post-quantum `liboqs`, `secp256k1-zkp`, and the VDF/PoW helpers), so most users
should build from the umbrella repository, which initialises those submodules
and wires the node together with the miner and verification services.

## Contributing & security

- Contribution workflow, the review (ACK/NACK) convention, and commit/signing
  policy are in [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Report vulnerabilities via the coordinated-disclosure process in
  [`SECURITY.md`](SECURITY.md). **Do not** open public issues for them.

## License

Released under the terms in [`COPYING`](COPYING).
