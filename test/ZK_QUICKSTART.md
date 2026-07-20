# ZK Test Vectors - Quick Reference

## Generate Vectors

```bash
cd test
./GENERATE_ZK_VECTORS.sh
```

## What You Get

**Output**: `functional/zk_test_vectors.py`

**Contents**: 3 BLS12-381 Groth16 proofs
- Valid proof
- Wrong asset_id (`zk-proof-bad`)
- Expired root (`zk-epoch-stale`)

## Prerequisites

**Need Go 1.21+**:
```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Test Coverage

### Unit Tests
- Segwit script validation
- Witness layout checks
- Proof count limits

Run: `./src/test/test_bitcoin --run_test=asset_zk_validation_tests`

### Functional Tests (require generated vectors)
- Cryptographic verification
- Proof binding to asset_id
- Root age validation

Run: `./test/functional/feature_asset_zk_validation.py`

## Files

| File | Purpose |
|------|---------|
| `GENERATE_ZK_VECTORS.sh` | Master script (run this) |
| `ZK_VECTORS_HOWTO.md` | Full documentation |
| `functional/zk_test_vectors.py` | Generated vectors |
| `functional/zk_circuits/gnark_generator/` | Generator source |

## Troubleshooting

**Go not found?** Install Go (see above)

**Proof size mismatch?** May need to implement point compression in `gnark_generator/main.go`

**Module errors?** `cd gnark_generator && go mod tidy`
