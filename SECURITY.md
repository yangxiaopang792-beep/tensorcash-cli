# Security Policy

`bcore` is the TensorCash consensus node. A vulnerability here can put funds and
network integrity at risk, so please disclose responsibly.

## Reporting a vulnerability

Report suspected vulnerabilities **privately** by email to
`security@tensorcash.org`.

**Do not** open a public GitHub issue, pull request, or discussion for a
suspected vulnerability, and do not disclose details publicly until a fix has
shipped and an agreed coordinated-disclosure window has elapsed. Premature
public disclosure of a consensus or wallet flaw exposes every node operator and
holder before they can update.

A useful report includes:

- a description of the issue and its security impact;
- the affected component (consensus, wallet, P2P/networking, or build);
- the version, commit, or build affected;
- steps to reproduce, and a proof of concept where one exists.

We ask reporters to act in good faith: give us a reasonable opportunity to
investigate and remediate before any public disclosure, and avoid accessing,
modifying, or destroying data that is not your own while researching an issue.

## Scope

In scope are flaws in the consensus and wallet code of this repository,
including:

- **Consensus** — block and transaction validation, the asset and
  model-verification rules, and the script interpreter (`src/consensus`,
  `src/script`, `src/validation.cpp`): for example consensus splits, validation
  bypasses, or rules that can be made to accept or reject blocks or transactions
  incorrectly.
- **Wallet** — key handling, transaction and covenant construction, and the
  wallet RPC surface (`src/wallet`): for example loss or exposure of key
  material, or the construction of unintended or unauthorized spends.
- **Networking and node integrity** — the P2P layer and RPC server
  (`src/net_processing.cpp`, `src/rpc`): for example remote crashes, resource
  exhaustion, or unauthenticated access to privileged RPCs.

The full project security policy is maintained in the umbrella repository:
<https://github.com/tensorcash/tensorcash/blob/main/SECURITY.md>.

## Handling

Consensus-critical fixes are coordinated with node operators so the network can
upgrade together, and details are withheld until enough of the network has
updated to make public disclosure safe.
