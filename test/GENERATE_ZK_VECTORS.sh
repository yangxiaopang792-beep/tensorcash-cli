#!/bin/bash
# Master script to generate ZK test vectors for TensorCash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR_DIR="$SCRIPT_DIR/functional/zk_circuits/gnark_generator"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  TensorCash ZK Test Vector Generation"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "This will generate REAL BLS12-381 Groth16 proofs for testing."
echo ""
echo "Prerequisites:"
echo "  • Go 1.21+ (will check)"
echo "  • ~2GB disk space for dependencies"
echo "  • ~30 seconds to generate proofs"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi
echo ""

cd "$GENERATOR_DIR"
./GENERATE.sh

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Done!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Test vectors generated at:"
echo "  $SCRIPT_DIR/functional/zk_test_vectors.py"
echo ""
echo "Run tests with:"
echo "  ./test/functional/feature_asset_zk_validation.py"
echo ""
