# TensorCash CLI wallet binaries

Developer-built command-line binaries for TensorCash on Linux x86_64.

Source project: [tensorcash/tensorcash](https://github.com/tensorcash/tensorcash)  
Source fork: [kinger2023/tensorcash](https://github.com/kinger2023/tensorcash)

## Included programs

- `bitcoind` — headless TensorCash node and wallet daemon
- `bitcoin-cli` — command-line RPC client
- `bitcoin-wallet` — offline wallet utility
- Manual pages for all three programs

## Release

The `v29.99.0` release provides `tensorcash-cli.tar.gz`, a developer-compiled Linux x86_64 build.

SHA256:

```text
d14542c48cdd785b523090cdf1f970763e59d5b0eb31e6ce28f8d1b357ec0abb  tensorcash-cli.tar.gz
```

## Verification

```bash
sha256sum tensorcash-cli.tar.gz
tar -tzf tensorcash-cli.tar.gz
```

This is a developer-provided binary distribution hosted separately from the upstream project's official releases. Verify the checksum before use. Wallet users should back up wallet data and private keys before upgrading.
