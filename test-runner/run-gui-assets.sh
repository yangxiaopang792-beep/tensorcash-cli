#!/bin/bash
# Wrapper to run the GUI assets test with proper setup

set -euo pipefail

echo "=== TensorCash GUI Asset Test Runner ==="
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
echo "Setting up GUI test script..."
cp /build/bcore/test-runner/gui-assets-simple.py "$TEST_DIR/functional/gui_assets_simple.py"

# Change to test directory and run
cd "$TEST_DIR/functional"

echo "Starting GUI asset test..."
echo "This will:"
echo "  1. Start VNC server on port 5901"
echo "  2. Create blockchain with assets"
echo "  3. Launch GUI with assets"
echo "  4. Keep mining blocks"
echo ""
echo "Connect via VNC: vnc://localhost:5901 (password: password)"
echo ""

# Run the test
python3 gui_assets_simple.py --configfile="../config.ini" --tmpdir="/root/tensorcash-gui"