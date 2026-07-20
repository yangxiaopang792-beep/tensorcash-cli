# How to Generate BLS12-381 ZK Test Vectors

## Quick Start

```bash
cd test
./GENERATE_ZK_VECTORS.sh
```

This produces working BLS12-381 Groth16 proofs.

## What This Does

1. **Installs gnark** (Go library for BLS12-381 Groth16)
2. **Compiles circuit** (minimal KYC compliance proof)
3. **Generates 3 test vectors**:
   - Valid proof (should pass)
   - Wrong asset_id (should fail: `zk-proof-bad`)
   - Expired root (should fail: `zk-epoch-stale`)
4. **Converts to TensorCash format** (192-byte proof + 128-byte inputs)
5. **Outputs**: `functional/zk_test_vectors.py`

## Prerequisites

### Install Go (if needed)

```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

Verify: `go version` should show `go1.21.6`

## Manual Steps (if you want control)

```bash
cd test/functional/zk_circuits/gnark_generator

# 1. Build generator
go mod download
go build -o zkgen .

# 2. Generate proofs
./zkgen

# 3. Convert to TensorCash format
python3 convert_vectors.py

# Output: ../../zk_test_vectors.py
```

## What You Get

### zk_test_vectors.py

```python
VECTORS = [
    ZkTestVector(
        name="valid_basic",
        proof_hex="<192 bytes>",
        public_inputs_hex="<128 bytes>",
        vk_hex="<VK bytes>",
        should_pass=True
    ),
    ZkTestVector(
        name="wrong_asset_id",
        proof_hex="<192 bytes>",
        public_inputs_hex="<128 bytes>",
        vk_hex="<VK bytes>",
        should_pass=False,
        expected_error="zk-proof-bad"
    ),
    # ...
]
```

### Using in Tests

```python
# test/functional/feature_asset_zk_validation.py
from zk_test_vectors import VECTORS

def test_proof_verification(self):
    node = self.nodes[0]

    for vec in VECTORS:
        # Create transaction with proof
        tx = create_kyc_spend_tx(
            proof=vec.proof,
            public_inputs=vec.public_inputs
        )

        if vec.should_pass:
            # Should accept
            node.sendrawtransaction(tx)
        else:
            # Should reject with expected error
            assert_raises_rpc_error(-26, vec.expected_error,
                node.sendrawtransaction, tx)
```

## Proof Format Details

### BLS12-381 Groth16 Proof (192 bytes)

| Component | Size | Description |
|-----------|------|-------------|
| A | 48 bytes | G1 point (compressed) |
| B | 96 bytes | G2 point (compressed) |
| C | 48 bytes | G1 point (compressed) |

### Public Inputs (128 bytes = 4 × 32 bytes)

| Index | Field | Description |
|-------|-------|-------------|
| 0 | chain_separator | Prevents cross-chain replay |
| 1 | asset_id | Binds proof to asset |
| 2 | compliance_root | Merkle root \|\| height |
| 3 | tfr_anchor | Transfer reporting commit |

### Verification Key (Variable)

| Field | Size | Description |
|-------|------|-------------|
| gamma_abc_count | 2 bytes | Number of public inputs (LE) |
| alpha_G1 | 48 bytes | G1 point |
| beta_G2 | 96 bytes | G2 point |
| gamma_G2 | 96 bytes | G2 point |
| delta_G2 | 96 bytes | G2 point |
| gamma_abc[0] | 48 bytes | G1 point |
| gamma_abc[1..n] | 48 bytes each | G1 points |

## Circuit Logic

The test circuit proves:

1. **Holder knows secret**: `MiMC(secret) == pubkey_hash`
2. **Bound to chain**: `chain_separator != 0`
3. **Bound to asset**: `asset_id != 0`

This is a minimal test circuit. A production circuit would include:

- Merkle proof verification (holder in whitelist)
- Timestamp/expiry validation
- Regulatory compliance checks

## Troubleshooting

### Error: "proof size mismatch"

**Cause**: gnark serialization != TensorCash format

**Fix**: You may need to implement proper G1/G2 point compression in `gnark_generator/main.go`:

```go
func serializeProof(proof groth16.Proof) []byte {
    // Extract G1/G2 affine coordinates
    // Compress according to BLS12-381 spec
    // Return 192 bytes (48 + 96 + 48)
}
```

See: https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-10.html

### Error: "Go not found"

```bash
# Install Go 1.21+
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### Error: "module not found"

```bash
cd functional/zk_circuits/gnark_generator
go mod download
go mod tidy
```

## Testing the Vectors

```bash
# Run functional test with real vectors
./test/functional/feature_asset_zk_validation.py

# Run unit tests (validation logic)
./src/test/test_bitcoin --run_test=asset_zk_validation_tests
```

## Why This Works (vs circom/snarkjs)

| Tool | Curve | TensorCash Compatible? |
|------|-------|------------------------|
| circom/snarkjs | BN254 | No (different curve) |
| gnark | BLS12-381 | Yes (native support) |
| bellman | BLS12-381 | Yes (Rust) |
| arkworks | BLS12-381 | Yes (Rust) |

TensorCash uses the BLST library for BLS12-381. gnark outputs native BLS12-381 proofs that work directly.

## Files

```
test/
├── GENERATE_ZK_VECTORS.sh          # One-command master script
├── ZK_VECTORS_HOWTO.md             # This file
│
├── functional/
│   ├── feature_asset_zk_validation.py    # Functional tests
│   ├── zk_test_vectors.py                # Generated vectors (OUTPUT)
│   │
│   └── zk_circuits/
│       ├── ZK_TEST_SETUP.md              # Detailed setup guide
│       │
│       └── gnark_generator/
│           ├── README.md                  # Generator docs
│           ├── GENERATE.sh                # Build + generate script
│           ├── build.sh                   # Build only
│           ├── go.mod                     # Go dependencies
│           ├── circuit.go                 # Circuit definition
│           ├── main.go                    # Proof generator
│           ├── convert_vectors.py         # Format converter
│           ├── test_vectors.json          # Intermediate output
│           └── zkgen                      # Compiled binary
│
└── src/test/
    └── asset_zk_validation_tests.cpp     # Unit tests
```
