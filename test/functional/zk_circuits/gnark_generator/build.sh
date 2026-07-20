#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=== Building TensorCash ZK Test Vector Generator ==="
echo ""

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "ERROR: Go not installed. Install with:"
    echo "  wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz"
    echo "  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz"
    echo "  export PATH=\$PATH:/usr/local/go/bin"
    exit 1
fi

echo "Go version: $(go version)"
echo ""

# Download dependencies
echo "Downloading dependencies..."
go mod download
echo ""

# Build
echo "Building generator..."
go build -o zkgen .
echo ""

# Run
echo "Generating test vectors..."
./zkgen
echo ""

echo "✓ Done! Test vectors written to test_vectors.json"
echo ""
echo "Next: Run convert_vectors.py to format for TensorCash"
