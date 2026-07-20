# Contributing to bcore

`bcore` is the consensus node for TensorCash. The contribution workflow, the
review (ACK/NACK) convention, and the commit sign-off / GPG-signing policy are
defined once for the whole project in the umbrella repository, and this
repository follows them:

<https://github.com/tensorcash/tensorcash/blob/main/CONTRIBUTING.md>

## Building

See [`INSTALL.md`](INSTALL.md) for the entry point and the per-platform guides
under [`doc/`](doc/) (`build-unix.md`, `build-osx.md`, `build-windows.md`,
`build-freebsd.md`). `bcore` depends on the TensorCash shared utilities
(post-quantum `liboqs`, `secp256k1-zkp`, the VDF and PoW helpers); the simplest
path is to build from the umbrella
[`tensorcash`](https://github.com/tensorcash/tensorcash) repository, which
initialises those submodules and wires the node together with the miner and
verification services.

## Running the tests

Add or update tests for any behaviour change.

- **Unit tests** — built with the tree (`cmake --build build --target
  test_bitcoin`) and run via the produced `test_bitcoin` binary or `ctest` from
  the build directory.
- **Functional tests** — Python integration tests driven by
  [`test/functional/test_runner.py`](test/functional/test_runner.py); pass a
  test name to run a single case or no argument to run the suite.
- **Linting** — checks live under [`lint/`](lint/).

## Pull requests

- **`main` is protected** — changes land via reviewed pull requests with green
  CI. No direct pushes, no force-pushes, linear history. (CI runs in the
  umbrella, which checks out `bcore` at the proposed commit and rebuilds.)
- Keep each pull request focused on one logical change, match the surrounding
  code style, and write clear, imperative commit subjects with a body that
  explains *why* when it isn't obvious.
- Sign off every commit (`git commit -s`) per the Developer Certificate of
  Origin.
- Reviewers respond with the ACK/NACK convention described in the umbrella
  guide; a maintainer merges only when a change has sufficient ACKs and no
  unresolved NACKs.

## Consensus changes

Because this repository carries consensus rules, treat any change to validation
behaviour with extra care:

- **Consensus-affecting changes require an accepted TIP** (TensorCash
  Improvement Proposal) before the implementation can merge — this includes
  script/opcode changes, asset/ICU/TLV formats, PoW/VDF/block-format changes,
  ZK/KYC enforcement, and economic parameters. See
  <https://github.com/tensorcash/tensorcash/tree/main/tips>.
- Bug fixes that do **not** change consensus, plus tests and docs, follow the
  ordinary pull-request flow without a TIP.

Report vulnerabilities via [`SECURITY.md`](SECURITY.md), never as a public issue.
