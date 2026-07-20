#!/usr/bin/env python3
"""
Convert gnark-generated test vectors to TensorCash format.

TensorCash expects:
- Proof: G1(48) + G2(96) + G1(48) = 192 bytes (BLS12-381 compressed)
- Public Inputs: 4 x 32 bytes = 128 bytes
- VK: Custom format with count header + G1/G2 points
"""

import json
import sys
import struct
from typing import Dict, List

def convert_proof_to_compressed(gnark_proof_hex: str) -> str:
    """
    Convert gnark proof format to TensorCash BLS12-381 compressed format.

    gnark outputs raw serialization, we need to extract and compress G1/G2 points.
    """
    # TODO: Implement proper point compression
    # For now, validate size and return as-is
    proof_bytes = bytes.fromhex(gnark_proof_hex)

    # BLS12-381 Groth16 proof is 3 points: A (G1), B (G2), C (G1)
    # Compressed: 48 + 96 + 48 = 192 bytes
    expected_size = 192

    if len(proof_bytes) != expected_size:
        print(f"WARNING: Proof size {len(proof_bytes)} != expected {expected_size}")
        print(f"You may need to implement proper G1/G2 point compression")
        # Pad or truncate
        if len(proof_bytes) < expected_size:
            proof_bytes = proof_bytes + b'\x00' * (expected_size - len(proof_bytes))
        else:
            proof_bytes = proof_bytes[:expected_size]

    return proof_bytes.hex()

def convert_public_inputs(gnark_inputs_hex: str) -> str:
    """
    Ensure public inputs are in TensorCash format (4 x 32 bytes = 128 bytes).
    """
    inputs_bytes = bytes.fromhex(gnark_inputs_hex)
    expected_size = 128  # 4 inputs * 32 bytes

    if len(inputs_bytes) != expected_size:
        print(f"WARNING: Public inputs size {len(inputs_bytes)} != expected {expected_size}")
        if len(inputs_bytes) < expected_size:
            inputs_bytes = inputs_bytes + b'\x00' * (expected_size - len(inputs_bytes))
        else:
            inputs_bytes = inputs_bytes[:expected_size]

    return inputs_bytes.hex()

def convert_vk_to_tensorcash_format(gnark_vk_hex: str) -> str:
    """
    Convert gnark VK to TensorCash format:
    - 2 bytes: gamma_abc_count (little-endian)
    - G1 point: alpha_G1 (48 bytes compressed)
    - G2 point: beta_G2 (96 bytes compressed)
    - G2 point: gamma_G2 (96 bytes compressed)
    - G2 point: delta_G2 (96 bytes compressed)
    - G1 point: gamma_abc[0] (48 bytes compressed)
    - G1 points: gamma_abc[1..n] (48 bytes each)
    """
    # TODO: Implement proper VK format conversion
    # For now, return raw with count header
    vk_bytes = bytes.fromhex(gnark_vk_hex)

    # Assume 4 public inputs = 4 gamma_abc elements
    gamma_abc_count = 4
    header = struct.pack('<H', gamma_abc_count)

    return (header + vk_bytes).hex()

def convert_vectors(input_file: str, output_file: str):
    """Convert gnark test vectors to TensorCash format."""

    print(f"Converting {input_file} to {output_file}...")

    with open(input_file, 'r') as f:
        gnark_vectors = json.load(f)

    tensorcash_vectors = []

    for vec in gnark_vectors:
        converted = {
            'name': vec['name'],
            'description': vec['description'],
            'proof_hex': convert_proof_to_compressed(vec['proof_hex']),
            'public_inputs_hex': convert_public_inputs(vec['public_inputs_hex']),
            'vk_hex': convert_vk_to_tensorcash_format(vec['vk_hex']),
            'should_pass': vec['should_pass'],
            'expected_error': vec.get('expected_error'),
            'witness': vec['witness']
        }
        tensorcash_vectors.append(converted)

        # Print summary
        proof_size = len(bytes.fromhex(converted['proof_hex']))
        inputs_size = len(bytes.fromhex(converted['public_inputs_hex']))
        vk_size = len(bytes.fromhex(converted['vk_hex']))

        status = "PASS" if vec['should_pass'] else f"FAIL ({vec.get('expected_error', 'unknown')})"
        print(f"  ✓ {vec['name']}: {status}")
        print(f"    - Proof: {proof_size} bytes")
        print(f"    - Public Inputs: {inputs_size} bytes")
        print(f"    - VK: {vk_size} bytes")

    # Write Python test vectors file
    with open(output_file, 'w') as f:
        f.write('#!/usr/bin/env python3\n')
        f.write('"""BLS12-381 Groth16 Test Vectors for TensorCash"""\n\n')
        f.write('class ZkTestVector:\n')
        f.write('    def __init__(self, name, proof_hex, public_inputs_hex, vk_hex, should_pass, expected_error=None, witness=None):\n')
        f.write('        self.name = name\n')
        f.write('        self.proof = bytes.fromhex(proof_hex)\n')
        f.write('        self.public_inputs = bytes.fromhex(public_inputs_hex)\n')
        f.write('        self.vk = bytes.fromhex(vk_hex)\n')
        f.write('        self.should_pass = should_pass\n')
        f.write('        self.expected_error = expected_error\n')
        f.write('        self.witness = witness or {}\n\n')

        f.write('VECTORS = [\n')
        for vec in tensorcash_vectors:
            f.write(f'    ZkTestVector(\n')
            f.write(f'        name="{vec["name"]}",\n')
            f.write(f'        proof_hex="{vec["proof_hex"]}",\n')
            f.write(f'        public_inputs_hex="{vec["public_inputs_hex"]}",\n')
            f.write(f'        vk_hex="{vec["vk_hex"]}",\n')
            f.write(f'        should_pass={vec["should_pass"]},\n')
            if vec['expected_error']:
                f.write(f'        expected_error="{vec["expected_error"]}",\n')
            f.write(f'        witness={json.dumps(vec["witness"])}\n')
            f.write(f'    ),\n')
        f.write(']\n')

    print(f"\n✓ Converted {len(tensorcash_vectors)} vectors to {output_file}")
    print(f"\nNOTE: This conversion assumes proper G1/G2 point compression.")
    print(f"You may need to implement actual point compression if gnark's")
    print(f"serialization doesn't match TensorCash's expected format.")

if __name__ == '__main__':
    input_file = 'test_vectors.json'
    output_file = '../../zk_test_vectors.py'

    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]

    convert_vectors(input_file, output_file)
