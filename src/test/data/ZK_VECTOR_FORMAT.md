# ZK Test Vector Format Specification

## Overview

This document specifies the format for Groth16 zero-knowledge proof test vectors used in TensorCash ZK testing. These vectors are used to test the verification logic without requiring a full ZK prover during development.

## Binary Format

All test vectors use the BLS12-381 elliptic curve. Data is serialized in compressed form.

### Field Elements (Fr)
- **Size**: 32 bytes
- **Encoding**: Big-endian
- **Constraint**: Must be < r (scalar field modulus, ~2^255)

### G1 Points
- **Size**: 48 bytes (compressed)
- **Format**: Compressed affine coordinates
- **Compression bit**: MSB of first byte indicates compression and infinity

### G2 Points
- **Size**: 96 bytes (compressed)
- **Format**: Compressed affine coordinates (two field elements)
- **Compression bit**: MSB of first byte indicates compression and infinity

## Proof Format

Total size: 192 bytes

```
Offset | Size | Description
-------|------|------------
0      | 48   | A (G1 point, compressed)
48     | 96   | B (G2 point, compressed)
144    | 48   | C (G1 point, compressed)
```

## Verifying Key Format

Variable size based on number of public inputs.

```
Offset | Size  | Description
-------|-------|------------
0      | 2     | gamma_abc_count (uint16, little-endian)
2      | 48    | alpha_G1 (compressed)
50     | 96    | beta_G2 (compressed)
146    | 96    | gamma_G2 (compressed)
242    | 96    | delta_G2 (compressed)
338    | 48    | gamma_abc[0] (G1, compressed)
386    | 48*n  | gamma_abc[1..n] (G1 points, compressed)
```

Where `n` is the value of `gamma_abc_count`.

## Public Inputs Format

For TensorCash KYC assets, we have exactly 4 public inputs:

```
Offset | Size | Field          | Description
-------|------|----------------|------------
0      | 32   | Chain Separator| Asset-specific chain identifier
32     | 32   | Asset ID       | The asset being transferred
64     | 32   | Root Height    | Block height of compliance root
96     | 32   | TFR Anchor     | Transfer restriction commitment
```

Each field is a 32-byte field element (Fr) in big-endian format.

### Special Encoding Rules

1. **Root Height**: Stored as uint32 in the last 4 bytes of the field element
2. **Asset ID**: Full 256-bit identifier, must be < modulus
3. **TFR Anchor**: 256-bit commitment hash, must be < modulus

## Test Vector Files

### Pre-generated Vectors (zk_test_vectors.h)

Located at: `src/test/data/zk_test_vectors.h`

Contains hardcoded byte arrays for:
- Valid G1/G2 points (generator and small multiples)
- Valid field elements
- Example proofs that are structurally valid but fail pairing

### Dynamic Generation (generate_zk_test_vectors.py)

Located at: `src/test/data/generate_zk_test_vectors.py`

Python script to generate test vectors using actual ZK provers:
- arkworks-rs integration
- gnark integration
- py-arkworks integration

## Validation Levels

### Level 1: Structural Validity
- Points are on the curve
- Points are in the correct subgroup
- Field elements are < modulus

### Level 2: Context Validation
- Root age checks
- Anchor matching
- Public input extraction

### Level 3: Cryptographic Validity
- Pairing equation verification
- Actual proof validation

## Generation Instructions

### Using blst (C++)
```cpp
#include <blst.h>

// Generate G1 point
blst_p1_affine g1;
blst_p1_generator(&g1);
unsigned char compressed[48];
blst_p1_affine_compress(compressed, &g1);
```

### Using arkworks-rs (Rust)
```rust
use ark_bls12_381::{G1Affine, G1Projective};
use ark_serialize::CanonicalSerialize;

let g1 = G1Projective::generator();
let mut bytes = Vec::new();
g1.serialize_compressed(&mut bytes)?;
```

### Using py-arkworks (Python)
```python
from py_arkworks_bls12381 import G1Point

g1 = G1Point.generator()
compressed = g1.to_compressed_bytes()
```

## Conditional Compilation

Test vectors are conditionally compiled based on the `BUILD_ZK_TESTS` CMake flag:

- **BUILD_ZK_TESTS=ON**: Uses blst to generate valid curve points dynamically
- **BUILD_ZK_TESTS=OFF**: Uses pre-generated hardcoded vectors

To enable full ZK testing:
```bash
cmake -DBUILD_ZK_TESTS=ON ..
```

## References

- BLS12-381: https://hackmd.io/@benjaminion/bls12-381
- Groth16: https://eprint.iacr.org/2016/260
- blst library: https://github.com/supranational/blst
- arkworks: https://github.com/arkworks-rs