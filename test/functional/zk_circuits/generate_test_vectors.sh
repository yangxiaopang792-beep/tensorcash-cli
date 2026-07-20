#!/bin/bash
# Generate ZK test vectors for TensorCash

set -e

CIRCUIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_NAME="kyc_compliance"
BUILD_DIR="${CIRCUIT_DIR}/build"

echo "=== TensorCash ZK Test Vector Generation ==="
echo ""

# Check dependencies
if ! command -v circom &> /dev/null; then
    echo "ERROR: circom not found. Install with:"
    echo "  npm install -g circom"
    exit 1
fi

if ! command -v snarkjs &> /dev/null; then
    echo "ERROR: snarkjs not found. Install with:"
    echo "  npm install -g snarkjs"
    exit 1
fi

# Check for circomlib
if [ ! -d "${CIRCUIT_DIR}/../../../../../../../node_modules/circomlib" ]; then
    echo "ERROR: circomlib not found. Install with:"
    echo "  cd $(dirname $CIRCUIT_DIR)/../../../../../../../ && npm install circomlib"
    exit 1
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "[1/8] Compiling circuit..."
circom "${CIRCUIT_DIR}/${CIRCUIT_NAME}.circom" --r1cs --wasm --sym --c

echo ""
echo "[2/8] Generating witness calculator..."
cd "${CIRCUIT_NAME}_js"
node generate_witness.js "${CIRCUIT_NAME}.wasm" ../../input.json ../witness.wtns
cd ..

echo ""
echo "[3/8] Setting up Powers of Tau (phase 1)..."
if [ ! -f powersOfTau28_hez_final_10.ptau ]; then
    echo "Downloading powers of tau..."
    wget -q https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau
fi

echo ""
echo "[4/8] Generating zkey (phase 2)..."
snarkjs groth16 setup ${CIRCUIT_NAME}.r1cs powersOfTau28_hez_final_10.ptau ${CIRCUIT_NAME}_0000.zkey

echo ""
echo "[5/8] Contributing to phase 2 (random beacon)..."
snarkjs zkey contribute ${CIRCUIT_NAME}_0000.zkey ${CIRCUIT_NAME}_final.zkey --name="Test" -e="test entropy" -v

echo ""
echo "[6/8] Exporting verification key..."
snarkjs zkey export verificationkey ${CIRCUIT_NAME}_final.zkey verification_key.json

echo ""
echo "[7/8] Generating proof..."
snarkjs groth16 prove ${CIRCUIT_NAME}_final.zkey witness.wtns proof.json public.json

echo ""
echo "[8/8] Verifying proof locally..."
snarkjs groth16 verify verification_key.json public.json proof.json

echo ""
echo "=== Test vectors generated successfully ==="
echo "Location: ${BUILD_DIR}"
echo ""
echo "Next steps:"
echo "1. Extract proof/vk from JSON files"
echo "2. Convert to TensorCash format (BLS12-381 compressed)"
echo "3. Add to test_vectors.py"
