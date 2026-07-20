#!/bin/bash
# Wrapper to run the clean GUI assets test

set -euo pipefail

echo "=== TensorCash Clean GUI Asset Test Runner ==="
echo ""

BUILD_DIR="${BUILD_DIR:-/build/bcore/build}"
BASE_DIR="${BASE_DIR:-/build/bcore}"
TEST_DIR="$BASE_DIR/test"

# Create test directory
mkdir -p "$TEST_DIR"

# Create config.ini if missing
if [ ! -f "$TEST_DIR/config.ini" ]; then
  echo "Creating config.ini..."
  cat >"$TEST_DIR/config.ini" <<CONFIG
[environment]
BUILDDIR=$BUILD_DIR
SRCDIR=$BASE_DIR
EXEEXT=
[components]
ENABLE_WALLET=true
ENABLE_CLI=true
ENABLE_BITCOIND=true
ENABLE_ZMQ=true
CONFIG
fi

# Copy the GUI test script to the functional test directory
echo "Setting up clean GUI test script..."
cp /build/bcore/test-runner/gui-assets-clean.py "$TEST_DIR/functional/gui_assets_clean.py"

# Change to test directory and run
cd "$TEST_DIR/functional"

echo "Starting clean GUI asset test..."
echo "This will:"
echo "  1. Start VNC server on port 5901"
echo "  2. Run node0 and node1 as bitcoind"
echo "  3. Create and mint assets on node0"
echo "  4. Launch GUI as a SEPARATE third node"
echo "  5. Send assets from node0 to the GUI wallet"
echo "  6. Keep mining blocks"
echo ""
echo "Connect via VNC: vnc://localhost:5901 (password: password)"
echo ""

# Run the test
python3 gui_assets_clean.py --configfile="../config.ini" --tmpdir="/root/tensorcash-gui"