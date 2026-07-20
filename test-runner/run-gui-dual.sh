#!/bin/bash
# Wrapper to run the dual GUI asset test

set -euo pipefail

echo "=== TensorCash Dual GUI Asset Test Runner ==="
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

# Copy the dual GUI test script to the functional test directory
echo "Setting up dual GUI test script..."
cp /build/bcore/test-runner/gui-assets-dual.py "$TEST_DIR/functional/gui_assets_dual.py"

# Change to test directory and run
cd "$TEST_DIR/functional"

echo "Starting dual GUI asset test..."
echo "This will:"
echo "  1. Start VNC server :1 on port 5901 for GUI1"
echo "  2. Start VNC server :2 on port 5902 for GUI2"
echo "  3. Run node0 and node1 as bitcoind nodes"
echo "  4. Create and mint assets on node0"
echo "  5. Launch GUI1 as a separate wallet node"
echo "  6. Launch GUI2 as another separate wallet node"
echo "  7. Send assets to both GUI wallets"
echo "  8. Keep mining blocks"
echo ""
echo "Connect via VNC:"
echo "  GUI1: vnc://localhost:5901 (password: password)"
echo "  GUI2: vnc://localhost:5902 (password: password)"
echo ""
echo "Test wallet-to-wallet transactions between the two GUI wallets!"
echo ""

# Run the test
python3 gui_assets_dual.py --configfile="../config.ini" --tmpdir="/root/tensorcash-dual-gui"
