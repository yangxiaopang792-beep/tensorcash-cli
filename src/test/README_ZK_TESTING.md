# ZK Testing Guide

## Overview

ZK proof verification rejects malformed input at the first blst validation step,
before reaching the logic under test. Naive mock data made from random bytes
(invalid G1/G2 curve points, field elements exceeding the modulus) therefore
cannot exercise the verifier's context checks. The test helpers in this directory
provide structurally valid data that passes parsing, so tests can target the
intended logic.

### 1. Valid Test Helpers (`zk_valid_test_helpers.h`)
- Uses blst to generate valid curve points
- Ensures field elements are < modulus
- Creates structurally valid (but cryptographically failing) test data

### 2. Testable Refactoring (`groth16_testable.h`)
- Separates context validation from cryptographic verification
- Allows testing root age and anchor logic independently
- Enables unit testing without full proof verification

### 3. Test Vector Generation
- Script to generate real Groth16 proofs (`generate_zk_test_vectors.py`)

## Running Tests

```bash
# Build with blst dependency
cmake --build build --target test_bitcoin

# Run the valid tests
./build/bin/test_bitcoin --run_test=groth16_valid_tests

# Run all ZK tests
./build/bin/test_bitcoin --run_test="groth16*"
./build/bin/test_bitcoin --run_test="asset_zk*"
```

## Generating Real Test Vectors

To create actual valid proofs that pass verification:

### Option 1: Use arkworks-rs
```rust
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_bls12_381::{Bls12_381, Fr};

// Define your circuit
// Generate proving/verifying keys
// Create proofs
// Export to binary format
```

### Option 2: Use gnark (Go)
```go
import (
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Define circuit
// Compile and setup
// Generate proof
// Export for C++ tests
```

### Option 3: Use py-arkworks
```python
from py_arkworks_bls12381 import G1Point, G2Point, Scalar
from py_arkworks_groth16 import prove, verify, setup

# Define circuit
# Generate keys
# Create proof
# Export to hex
```

## Test Data Validity Levels

1. **Structurally Valid**: Passes blst parsing but fails pairing
   - Provided by the test helpers in this directory
   - Good for testing format validation and context checks

2. **Cryptographically Valid**: Actually verifies
   - Requires real prover
   - Needed for end-to-end testing

3. **Mock with Bypass**: Stub out pairing for unit tests
   - Fastest for CI
   - Requires refactoring verifier

## Test Coverage

| Test Type | Data Validity | What's Tested |
|-----------|--------------|---------------|
| `groth16_valid_tests` | Structurally valid | Format parsing, context validation |
| `asset_zk_consensus_tests` | N/A | Consensus logic without crypto |

## Notes

- The `ValidButFailingProof()` helper creates a proof that passes all format checks but fails the pairing equation
- Root age and anchor validation now work correctly with valid data
- For production testing, integrate with a real Groth16 prover