#!/bin/bash
# ONE-COMMAND SCRIPT TO GENERATE BLS12-381 TEST VECTORS

set -e

cd "$(dirname "$0")"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  TensorCash BLS12-381 Groth16 Test Vector Generator          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Check Go
echo "► Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo "✗ Go not found"
    echo ""
    echo "Install Go with:"
    echo "  wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz"
    echo "  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz"
    echo "  export PATH=\$PATH:/usr/local/go/bin"
    echo ""
    exit 1
fi
echo "✓ Go installed: $(go version | cut -d' ' -f3)"
echo ""

# Step 2: Download dependencies
echo "► Downloading gnark dependencies..."
go mod download 2>&1 | grep -v "^go:" || true
echo "✓ Dependencies downloaded"
echo ""

# Step 3: Build generator
echo "► Building proof generator..."
go build -o zkgen . 2>&1 | grep -v "^#" || true
echo "✓ Generator built: ./zkgen"
echo ""

# Step 4: Generate proofs
echo "► Generating BLS12-381 Groth16 proofs..."
./zkgen
echo ""

# Step 5: Convert to TensorCash format
echo "► Converting to TensorCash format..."
chmod +x convert_vectors.py
python3 convert_vectors.py
echo ""

# Step 6: Verify output
OUTPUT_FILE="../../zk_test_vectors.py"
if [ -f "$OUTPUT_FILE" ]; then
    VECTOR_COUNT=$(grep -c "ZkTestVector" "$OUTPUT_FILE" || echo "0")
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ✓ SUCCESS: Generated $VECTOR_COUNT test vectors                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Output: $OUTPUT_FILE"
    echo ""
    echo "Next steps:"
    echo "  1. Review: cat $OUTPUT_FILE"
    echo "  2. Test: ./test/functional/feature_asset_zk_validation.py"
    echo "  3. Verify point compression matches TensorCash format"
    echo ""
else
    echo "✗ Error: Output file not created"
    exit 1
fi
