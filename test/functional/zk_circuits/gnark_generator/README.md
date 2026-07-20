# BLS12-381 Groth16 Test Vector Generator

## What This Does

Generates **real BLS12-381 Groth16 proofs** for TensorCash ZK testing using [gnark](https://github.com/ConsenSys/gnark).

Unlike circom/snarkjs (BN254), gnark supports BLS12-381 natively, so these proofs will work with TensorCash's BLST-based verification.

## Quick Start

```bash
# 1. Install Go (if not installed)
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 2. Generate test vectors
cd test/functional/zk_circuits/gnark_generator
chmod +x build.sh
./build.sh

# 3. Convert to TensorCash format
python3 convert_vectors.py

# 4. Test vectors are now in ../../zk_test_vectors.py
```

## Generated Test Vectors

### Vector 1: Valid Proof
- **Should**: Pass verification
- **Tests**: Basic cryptographic verification works

### Vector 2: Wrong Asset ID
- **Should**: Fail with `zk-proof-bad`
- **Tests**: Proof binding to asset_id

### Vector 3: Expired Root
- **Should**: Fail with `zk-epoch-stale`
- **Tests**: Root age validation

## Circuit Design

The circuit (`circuit.go`) implements a minimal KYC compliance check:

**Public Inputs (matches TensorCash schema):**
1. `chain_separator` - Prevents cross-chain replay
2. `asset_id` - Binds proof to specific asset
3. `compliance_root` - Merkle root || height
4. `tfr_anchor` - Transfer reporting commitment

**Private Inputs:**
- `secret` - Holder's secret preimage
- `pubkey_hash` - Hash of secret (proves holder identity)

**Constraints:**
1. `MiMC(secret) == pubkey_hash` - Proves knowledge of secret
2. `chain_separator != 0` - Ensures binding to chain
3. `asset_id != 0` - Ensures binding to asset

## How It Works

### 1. Compile Circuit
```go
ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
```
Converts circuit to R1CS (Rank-1 Constraint System).

### 2. Groth16 Setup
```go
pk, vk, err := groth16.Setup(ccs)
```
Generates proving key (pk) and verification key (vk).

**Note:** This is a trusted setup. In production, use a proper ceremony.

### 3. Generate Witness
```go
witness := TensorCashKYCCircuit{
    ChainSeparator: big.NewInt(123456789),
    AssetID:        ...,
    // ... assign values
}
```

### 4. Generate Proof
```go
proof, err := groth16.Prove(ccs, pk, fullWitness)
```

### 5. Serialize
```go
proofBytes := serializeProof(proof)    // A, B, C points
publicInputs := serializePublicInputs() // 4 x 32 bytes
vkBytes := serializeVK(vk)             // VK with count header
```

## Output Format

### test_vectors.json (intermediate)
```json
{
  "name": "valid_basic",
  "proof_hex": "...",
  "public_inputs_hex": "...",
  "vk_hex": "...",
  "should_pass": true
}
```

### zk_test_vectors.py (final)
```python
VECTORS = [
    ZkTestVector(
        name="valid_basic",
        proof_hex="...",  # 192 bytes (48+96+48)
        public_inputs_hex="...",  # 128 bytes (4x32)
        vk_hex="...",
        should_pass=True
    ),
    # ...
]
```

## Using Test Vectors in Tests

```python
# test/functional/feature_asset_zk_validation.py
from zk_test_vectors import VECTORS

def test_proof_verification(self):
    for vec in VECTORS:
        if vec.should_pass:
            # Test should accept proof
            node.sendrawtransaction(tx_with_proof)
        else:
            # Test should reject with expected error
            assert_raises_rpc_error(-26, vec.expected_error,
                node.sendrawtransaction, tx_with_proof)
```

## Troubleshooting

### Issue: Proof size mismatch
**Cause**: gnark's serialization != TensorCash's expected format

**Fix**: Implement proper G1/G2 point compression in `serializeProof()`:
```go
// Extract affine coordinates from gnark proof
// Compress to BLS12-381 format (x-coordinate + sign bit)
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-10.html
```

### Issue: VK format incompatible
**Cause**: TensorCash expects specific VK layout

**Fix**: Implement proper VK serialization in `serializeVK()`:
```go
// Header: gamma_abc_count (2 bytes LE)
// alpha_G1 (48 bytes compressed)
// beta_G2 (96 bytes compressed)
// gamma_G2 (96 bytes compressed)
// delta_G2 (96 bytes compressed)
// gamma_abc[0] (48 bytes compressed)
// gamma_abc[1..n] (48 bytes each)
```

### Issue: Go not installed
```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

## References

- [gnark Documentation](https://docs.gnark.consensys.net/)
- [BLS12-381 Spec](https://github.com/supranational/blst#bls12-381-pairing)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [TensorCash groth16.cpp](../../../../src/crypto/groth16.cpp)
