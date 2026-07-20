#!/bin/bash

set -uo pipefail

echo "=== TensorCash GUI Asset Testing - Complete Setup ==="
echo ""

# Configuration
ROOT_DIR=/root
GUI_DIR=${ROOT_DIR}/tensorcash-test
TMP_ROOT=${ROOT_DIR}/tensorcash-functional
TEST_NAME=feature_assets_basic_highlevel
TEST_DIR=/build/bcore/test
CONFIG_FILE=${TEST_DIR}/config.ini
BITCOIND_BIN=/build/bcore/build/bin/bitcoind
BITCOINCLI_BIN=/build/bcore/build/bin/bitcoin-cli
BITCOIN_QT_BIN=/build/bcore/build/bin/bitcoin-qt
TEST_RUNNER=/build/bcore/test/functional/test_runner.py

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Step 1: Start VNC if needed
echo -e "${BLUE}Step 1: Checking VNC server...${NC}"
if ! xdpyinfo -display :1 >/dev/null 2>&1; then
    echo "Starting VNC server..."
    vncserver -kill :1 2>/dev/null || true
    rm -rf /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true
    vncserver :1 -geometry 1280x800 -depth 24
    echo -e "${GREEN}VNC server started on port 5901 (password: password)${NC}"
else
    echo "VNC server already running"
fi
export DISPLAY=:1

# Step 2: Run functional test to create blockchain with assets
echo ""
echo -e "${BLUE}Step 2: Creating blockchain with assets using functional test...${NC}"

# Clean previous runs
pkill -f "bitcoind.*tensorcash-test" 2>/dev/null || true
pkill -f "bitcoin-qt.*tensorcash-test" 2>/dev/null || true
sleep 2

# Setup test config
mkdir -p "${TEST_DIR}"
if [ ! -f "${CONFIG_FILE}" ]; then
    cat >"${CONFIG_FILE}" <<CONFIG
[environment]
BUILDDIR=/build/bcore/build
SRCDIR=/build/bcore
EXEEXT=
[components]
ENABLE_WALLET=true
ENABLE_CLI=true
ENABLE_BITCOIND=true
ENABLE_ZMQ=true
CONFIG
fi

# Run the functional test
echo "Running functional test to create assets..."
rm -rf "${TMP_ROOT}"
mkdir -p "${TMP_ROOT}"

cd /build/bcore/test/functional
if ! BITCOIND="${BITCOIND_BIN}" BITCOINCLI="${BITCOINCLI_BIN}" \
    python3 ./test_runner.py "${TEST_NAME}" --nocleanup --tmpdir="${TMP_ROOT}"; then
    echo -e "${YELLOW}Warning: Functional test had issues${NC}"
fi

# Find and copy the test results
RUN_DIR=$(ls -td "${TMP_ROOT}"/test_runner_* 2>/dev/null | head -n 1)
if [ -z "${RUN_DIR}" ]; then
    echo "Error: Could not find test results"
    exit 1
fi

RESULT_DIR=$(ls -td "${RUN_DIR}/${TEST_NAME}_"* 2>/dev/null | head -n 1)
if [ -z "${RESULT_DIR}" ]; then
    echo "Error: Could not find test datadir"
    exit 1
fi

# Sanity check: ensure asset registrations made it to disk before copying anything.
echo "Running pre-copy asset registry check..."
CHECK_PORT=39554
CHECK_RPC=39553

# Kill any leftover bitcoind processes that might be using these datadirs
pkill -f "bitcoind.*${RESULT_DIR}" 2>/dev/null || true
sleep 2

# Start node0 to validate and fully sync chainstate
"${BITCOIND_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -daemon \
    -listen=0 -discover=0 -dns=0 -dnsseed=0 -port=${CHECK_PORT} -rpcport=${CHECK_RPC} \
    -fallbackfee=0.00001 >/dev/null 2>&1

# Wait for startup
for i in {1..10}; do
    if "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} getblockcount >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Check if node actually started
if ! "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} getblockcount >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: validation node failed to start, trying with wallet load${NC}"
    # Try starting with wallet explicitly loaded
    "${BITCOIND_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -daemon \
        -listen=0 -discover=0 -dns=0 -dnsseed=0 -port=${CHECK_PORT} -rpcport=${CHECK_RPC} \
        -wallet="" -fallbackfee=0.00001 >/dev/null 2>&1

    # Wait again
    for i in {1..15}; do
        if "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} getblockcount >/dev/null 2>&1; then
            echo "Node started successfully on retry"
            break
        fi
        sleep 1
    done
fi

# Force a full chainstate flush to ensure all registrations are on disk
if "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} getblockcount >/dev/null 2>&1; then
    echo "Forcing chainstate flush on node0..."
    "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} gettxoutsetinfo >/dev/null 2>&1 || true
    sleep 2

    BALANCES_JSON=$("${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} getassetbalance 2>/dev/null | tr -d '\n')
    if [ -n "${BALANCES_JSON}" ] && [ "${BALANCES_JSON}" != "[]" ]; then
        export BALANCES_JSON
        export BITCOINCLI_BIN
        export RESULT_DIR
        export CHECK_RPC
        python3 - <<'PY'
import json
import os
import subprocess

balances = json.loads(os.environ.get("BALANCES_JSON", "[]"))
cli = os.environ["BITCOINCLI_BIN"]
datadir = os.path.join(os.environ["RESULT_DIR"], "node0")
rpcport = os.environ["CHECK_RPC"]

unregistered = []
for asset in balances:
    asset_id = asset.get("asset_id")
    if not asset_id:
        continue
    cmd = [
        cli,
        f"-datadir={datadir}",
        "-regtest",
        f"-rpcport={rpcport}",
        "getassetinfo",
        asset_id,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        unregistered.append((asset.get("ticker", ""), asset_id, res.stderr.strip()))

if unregistered:
    print("Detected assets without registry entries in functional output:")
    for ticker, asset_id, err in unregistered:
        label = ticker or asset_id[:8]
        print(f"  - {label}: {asset_id} ({err})")
    print("These assets will be flagged as unregistered in the GUI dataset.")
PY
    fi
else
    echo -e "${YELLOW}Warning: could not contact temporary validation node for asset check${NC}"
fi

"${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} stop >/dev/null 2>&1 || true

# Also sync node1's chainstate
echo "Forcing chainstate flush on node1..."
CHECK_PORT2=39564
CHECK_RPC2=39563
"${BITCOIND_BIN}" -datadir="${RESULT_DIR}/node1" -regtest -daemon \
    -listen=0 -discover=0 -dns=0 -dnsseed=0 -port=${CHECK_PORT2} -rpcport=${CHECK_RPC2} \
    -fallbackfee=0.00001 >/dev/null 2>&1

for i in {1..10}; do
    if "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node1" -regtest -rpcport=${CHECK_RPC2} getblockcount >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

"${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node1" -regtest -rpcport=${CHECK_RPC2} gettxoutsetinfo >/dev/null 2>&1 || true
"${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node1" -regtest -rpcport=${CHECK_RPC2} stop >/dev/null 2>&1 || true
sleep 2

# Copy datadirs
echo "Copying test results..."
rm -rf "${GUI_DIR}"
mkdir -p "${GUI_DIR}"
cp -a "${RESULT_DIR}/node0" "${GUI_DIR}/node1"
cp -a "${RESULT_DIR}/node1" "${GUI_DIR}/node2"

# Step 3: Launch GUI with the correct wallet
echo ""
echo -e "${BLUE}Step 3: Launching GUI wallet with assets...${NC}"

# Find where the wallet actually is - DO NOT MOVE ANYTHING
echo "Looking for wallet files..."
ls -la "${GUI_DIR}/node1/regtest/wallets/" 2>/dev/null || echo "No wallets directory"

# The functional test creates wallet.dat in wallets/ directory as the unnamed wallet
# This is the wallet with assets - we need to load it with -wallet=""
if [ -f "${GUI_DIR}/node1/regtest/wallets/wallet.dat" ]; then
    echo "Found unnamed wallet (wallet.dat) in wallets/ - this has the assets"
    WALLET_TO_LOAD=""
    WALLET_LOCATION="found"
elif [ -f "${GUI_DIR}/node1/regtest/wallet.dat" ]; then
    echo "Found wallet.dat at root level"
    WALLET_TO_LOAD=""
    WALLET_LOCATION="found"
else
    echo "ERROR: No wallet.dat found!"
    WALLET_LOCATION="none"
fi

if [ "$WALLET_LOCATION" = "found" ]; then
    echo "Starting Bitcoin-Qt GUI with the unnamed wallet..."

    # Load the unnamed wallet explicitly with -wallet=""
    DISPLAY=:1 "${BITCOIN_QT_BIN}" \
        -datadir="${GUI_DIR}/node1" \
        -regtest \
        -wallet="" &

    QT_PID=$!
    echo -e "${GREEN}GUI started with PID: $QT_PID${NC}"
    sleep 5

    # Verify assets are loaded
    echo ""
    echo "Verifying assets are loaded..."

    # Check what wallets are loaded
    echo "Checking loaded wallets..."
    LOADED_WALLETS=$($BITCOINCLI_BIN -datadir="${GUI_DIR}/node1" -regtest listwallets 2>/dev/null)
    echo "Loaded wallets: $LOADED_WALLETS"

    # Get balance and assets with the unnamed wallet
    BALANCE=$($BITCOINCLI_BIN -datadir="${GUI_DIR}/node1" -regtest -rpcwallet="" getbalance 2>/dev/null)
    echo "BTC Balance: $BALANCE"

    ASSETS=$($BITCOINCLI_BIN -datadir="${GUI_DIR}/node1" -regtest -rpcwallet="" getassetbalance 2>/dev/null)
    if [ -n "$ASSETS" ] && [ "$ASSETS" != "[]" ]; then
        echo -e "${GREEN}Assets found in wallet:${NC}"
        echo "$ASSETS" | python3 -c "
import sys, json
assets = json.load(sys.stdin)
for a in assets:
    print(f\"  - {a['ticker']}: {a['balance_decimal']} (ID: {a['asset_id'][:16]}...)\")"
    else
        echo -e "${YELLOW}No assets found in wallet${NC}"
        echo "This may indicate the wallet bug where asset-tagged UTXOs aren't visible"
    fi
else
    echo "Error: No wallet found in test results"
    echo "Test directory structure:"
    ls -la "${GUI_DIR}/node1/" 2>/dev/null || echo "node1 directory not found"
    ls -la "${GUI_DIR}/node1/regtest/" 2>/dev/null || echo "regtest directory not found"
    echo ""
    echo "This usually means the functional test didn't create a wallet properly"
    echo "You can try running the test manually:"
    echo "  cd /build/bcore/test/functional"
    echo "  python3 test_runner.py feature_assets_basic_highlevel --nocleanup"
    exit 1
fi

# Step 4: Start mining node and connect
echo ""
echo -e "${BLUE}Step 4: Starting mining node and establishing connection...${NC}"

# Start the mining node (node2)
echo "Starting mining node (node2)..."
"${BITCOIND_BIN}" -datadir="${GUI_DIR}/node2" -regtest -daemon \
    -port=28444 -rpcport=28443 \
    -connect=127.0.0.1:18444
sleep 3

# Verify mining node is running
if ! $BITCOINCLI_BIN -datadir="${GUI_DIR}/node2" -regtest -rpcport=28443 getblockchaininfo >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Mining node failed to start${NC}"
else
    echo "Mining node started successfully"

    # Create or load wallet for mining
    echo "Setting up mining wallet..."
    $BITCOINCLI_BIN -datadir="${GUI_DIR}/node2" -regtest -rpcport=28443 createwallet "miner" 2>/dev/null || \
    $BITCOINCLI_BIN -datadir="${GUI_DIR}/node2" -regtest -rpcport=28443 loadwallet "miner" 2>/dev/null || true
fi

# Connect the nodes
echo "Connecting nodes..."
$BITCOINCLI_BIN -datadir="${GUI_DIR}/node1" -regtest addnode "127.0.0.1:28444" "add"
$BITCOINCLI_BIN -datadir="${GUI_DIR}/node2" -regtest -rpcport=28443 addnode "127.0.0.1:18444" "add"
sleep 2

# Verify connection
PEER_COUNT=$($BITCOINCLI_BIN -datadir="${GUI_DIR}/node1" -regtest getconnectioncount)
echo "Node1 peer count: $PEER_COUNT"

# Start automatic mining in background
echo ""
echo -e "${BLUE}Step 5: Starting automatic block generation...${NC}"
echo "Mining a new block every 10 seconds..."

# Create mining script
cat > /tmp/mine_blocks.sh << 'EOF'
#!/bin/bash
BITCOINCLI="/build/bcore/build/bin/bitcoin-cli"
NODE2_DIR="/root/tensorcash-test/node2"
MINING_ADDR=$($BITCOINCLI -datadir="$NODE2_DIR" -regtest -rpcport=28443 -rpcwallet=miner getnewaddress)

echo "Mining to address: $MINING_ADDR"
echo "Mining blocks every 10 seconds. Press Ctrl+C to stop..."

while true; do
    BLOCKCOUNT=$($BITCOINCLI -datadir="$NODE2_DIR" -regtest -rpcport=28443 getblockcount)
    echo "[$(date '+%H:%M:%S')] Mining block $((BLOCKCOUNT + 1))..."
    $BITCOINCLI -datadir="$NODE2_DIR" -regtest -rpcport=28443 -rpcwallet=miner generatetoaddress 1 "$MINING_ADDR" >/dev/null
    sleep 10
done
EOF
chmod +x /tmp/mine_blocks.sh

# Run mining in background
/tmp/mine_blocks.sh &
MINING_PID=$!
echo "Background mining started with PID: $MINING_PID"

# Create helper aliases script for easier testing
cat > /tmp/test_aliases.sh << 'EOF'
#!/bin/bash
# Aliases for easier testing
alias tcli1="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node1 -regtest -rpcwallet=\"\""
alias tcli2="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node2 -regtest -rpcport=28443 -rpcwallet=miner"

# Helper functions
tbalance() {
    echo "Node1 (Wallet):"
    echo "  BTC: $(tcli1 getbalance)"
    echo "  Assets:"
    tcli1 getassetbalance | python3 -c "import sys, json; [print(f\"    {a['ticker']}: {a['balance_decimal']}\") for a in json.load(sys.stdin)]" 2>/dev/null || echo "    None"
    echo ""
    echo "Node2 (Miner):"
    echo "  BTC: $(tcli2 getbalance)"
    echo "  Block height: $(tcli2 getblockcount)"
}

tstatus() {
    echo "Network status:"
    echo "  Node1 connections: $(tcli1 getconnectioncount)"
    echo "  Node1 block height: $(tcli1 getblockcount)"
    echo "  Node2 block height: $(tcli2 getblockcount)"
}

echo "Test aliases loaded:"
echo "  tcli1    - Wallet node CLI"
echo "  tcli2    - Mining node CLI"
echo "  tbalance - Show all balances"
echo "  tstatus  - Show network status"
EOF
chmod +x /tmp/test_aliases.sh

echo ""
echo "Load test aliases with: source /tmp/test_aliases.sh"

# Step 5: Provide usage instructions
echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "The GUI should now be visible in VNC showing:"
echo "  - BTC balance: ~85 BTC"
echo "  - Asset balances in the Asset Balances section"
echo ""
echo "Live blockchain is running with:"
echo "  - Mining node (node2) generating blocks every 10 seconds"
echo "  - Wallet node (node1) connected and syncing"
echo ""
echo "To connect via VNC:"
echo "  Mac: vnc://localhost:5901 (password: password)"
echo ""
echo "CLI commands for testing:"
echo "  Wallet (node1):"
echo "    ${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node1 -regtest -rpcwallet=\"\" getbalance"
echo "    ${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node1 -regtest -rpcwallet=\"\" getassetbalance"
echo "    ${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node1 -regtest listassets"
echo ""
echo "  Mining node (node2):"
echo "    ${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node2 -regtest -rpcport=28443 getblockcount"
echo "    ${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node2 -regtest -rpcport=28443 getpeerinfo"
echo ""
echo "Active processes:"
echo "  GUI wallet: PID $QT_PID"
echo "  Mining script: PID $MINING_PID"
echo ""
echo "To stop mining: kill $MINING_PID"
echo "Press Ctrl+C to stop everything"

# Clean shutdown handler
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $MINING_PID 2>/dev/null || true
    $BITCOINCLI_BIN -datadir="${GUI_DIR}/node2" -regtest -rpcport=28443 stop 2>/dev/null || true
    kill $QT_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

# Keep script running
wait $QT_PID
