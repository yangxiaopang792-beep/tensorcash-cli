#!/bin/bash

set -uo pipefail  # Remove -e to continue on errors

echo "=== Direct Asset Setup for GUI Testing ==="
echo "This script sets up a regtest chain with registered assets for GUI wallet testing"
echo ""

# Configuration
ROOT_DIR=/root
GUI_DIR=${ROOT_DIR}/tensorcash-test
BITCOIND_BIN=/build/bcore/build/bin/bitcoind
BITCOINCLI_BIN=/build/bcore/build/bin/bitcoin-cli
BITCOIN_QT_BIN=/build/bcore/build/bin/bitcoin-qt

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# CLI aliases
CLI1="${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node1 -regtest -rpcuser=test -rpcpassword=test123"
CLI2="${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node2 -regtest -rpcuser=test -rpcpassword=test123 -rpcport=28443"

# Check binaries exist
if [ ! -x "${BITCOIND_BIN}" ] || [ ! -x "${BITCOINCLI_BIN}" ]; then
    echo -e "${RED}Error: bitcoind/bitcoin-cli binaries not found under /build/bcore/build/bin${NC}" >&2
    exit 1
fi

echo -e "${BLUE}Step 1: Clean and prepare directories${NC}"
# Stop any running nodes
pkill -f "bitcoind.*tensorcash-test" 2>/dev/null || true
pkill -f "bitcoin-qt.*tensorcash-test" 2>/dev/null || true
sleep 2

# Clean and recreate directories
rm -rf "${GUI_DIR}"
mkdir -p "${GUI_DIR}/node1" "${GUI_DIR}/node2"

echo "Creating configuration files..."

# Node 1 Config (GUI wallet) - with assets enabled at height 1
cat > "${GUI_DIR}/node1/bitcoin.conf" <<EOF
# Global settings
server=1
daemon=0
txindex=1
rpcuser=test
rpcpassword=test123
rpcallowip=127.0.0.1
printtoconsole=1

[regtest]
port=18444
rpcport=18443
listen=1
assetsheight=1
policymaxassetspertx=100
assetminfeerate=1
fallbackfee=0.00001
minrelaytxfee=0.00000100
EOF

# Node 2 Config (Mining node) - with assets enabled at height 1
cat > "${GUI_DIR}/node2/bitcoin.conf" <<EOF
# Global settings
server=1
daemon=1
txindex=1
rpcuser=test
rpcpassword=test123
rpcallowip=127.0.0.1
printtoconsole=1

[regtest]
port=28444
rpcport=28443
listen=1
connect=127.0.0.1:18444
assetsheight=1
policymaxassetspertx=100
assetminfeerate=1
fallbackfee=0.00001
minrelaytxfee=0.00000100
EOF

echo -e "${BLUE}Step 2: Start nodes${NC}"

# Start node1 FIRST since node2 will connect to it
echo "Starting node1 (wallet node)..."
"${BITCOIND_BIN}" -datadir="${GUI_DIR}/node1" -regtest -daemon
sleep 3

# Wait for node1 to be ready
echo "Waiting for node1 to start..."
for i in {1..30}; do
    if $CLI1 getblockchaininfo >/dev/null 2>&1; then
        echo "Node1 is ready"
        break
    fi
    sleep 1
done

# Now start node2 which will connect to node1
echo "Starting mining node (node2)..."
"${BITCOIND_BIN}" -datadir="${GUI_DIR}/node2" -regtest &
BITCOIND_PID=$!
echo "Mining node started with PID: $BITCOIND_PID"

# Wait for node2 to start
echo "Waiting for node2 to start..."
for i in {1..30}; do
    if $CLI2 getblockchaininfo >/dev/null 2>&1; then
        echo "Node2 is ready"
        break
    fi
    sleep 1
done

echo -e "${BLUE}Step 3: Create wallets and verify connection${NC}"

# Create wallets
$CLI1 createwallet "test_wallet" 2>/dev/null || echo "Test wallet already exists"
$CLI2 createwallet "miner" 2>/dev/null || echo "Miner wallet already exists"

# Verify nodes are connected (node2 should auto-connect to node1)
echo "Verifying node connection..."
sleep 2
PEER_COUNT1=$($CLI1 getconnectioncount)
PEER_COUNT2=$($CLI2 getconnectioncount)
echo "Node1 peers: $PEER_COUNT1, Node2 peers: $PEER_COUNT2"

if [ "$PEER_COUNT1" -eq 0 ] || [ "$PEER_COUNT2" -eq 0 ]; then
    echo "Nodes not connected, forcing connection..."
    $CLI2 addnode "127.0.0.1:18444" "onetry"
    $CLI1 addnode "127.0.0.1:28444" "onetry"
    sleep 2
    PEER_COUNT1=$($CLI1 getconnectioncount)
    PEER_COUNT2=$($CLI2 getconnectioncount)
    echo "After retry - Node1 peers: $PEER_COUNT1, Node2 peers: $PEER_COUNT2"
fi

echo -e "${BLUE}Step 4: Generate initial blocks and fund wallet${NC}"

# Generate blocks with miner
MINER_ADDR=$($CLI2 -rpcwallet=miner getnewaddress)
echo "Mining 150 blocks to: $MINER_ADDR"
$CLI2 -rpcwallet=miner generatetoaddress 150 "$MINER_ADDR" >/dev/null

# Get balance
MINER_BALANCE=$($CLI2 -rpcwallet=miner getbalance)
echo -e "${GREEN}Miner balance: $MINER_BALANCE BTC${NC}"

# Send funds to test wallet
TEST_ADDR=$($CLI1 -rpcwallet=test_wallet getnewaddress)
echo "Sending 20 BTC to test wallet address: $TEST_ADDR"
FUND_TX=$($CLI2 -rpcwallet=miner sendtoaddress "$TEST_ADDR" 20)
echo "Funding transaction: $FUND_TX"

# Mine a block to confirm
$CLI2 -rpcwallet=miner generatetoaddress 1 "$MINER_ADDR" >/dev/null
sleep 1

TEST_BALANCE=$($CLI1 -rpcwallet=test_wallet getbalance)
echo -e "${GREEN}Test wallet balance: $TEST_BALANCE BTC${NC}"

echo -e "${BLUE}Step 5: Register assets${NC}"

# Define asset IDs
GOLD_ID="1111111111111111111111111111111111111111111111111111111111111111"
SILVER_ID="2222222222222222222222222222222222222222222222222222222222222222"

# Register GOLD asset
echo "Registering GOLD asset..."
GOLD_ICU=$($CLI1 -rpcwallet=test_wallet getnewaddress)
GOLD_REG=$($CLI1 -rpcwallet=test_wallet registerasset \
    "$GOLD_ICU" \
    5.1 \
    "$GOLD_ID" \
    3 \
    28 \
    510000000 \
    "GOLD" \
    8 \
    '{"autofund":true,"broadcast":true}' 2>&1)

if [[ "$GOLD_REG" =~ ^[a-f0-9]{64}$ ]]; then
    echo -e "${GREEN}GOLD registration TX: ${GOLD_REG:0:16}...${NC}"

    # Verify TX is in node1's mempool first
    NODE1_MEMPOOL=$($CLI1 getrawmempool 2>/dev/null)
    if ! echo "$NODE1_MEMPOOL" | grep -q "$GOLD_REG"; then
        echo "ERROR: TX not even in node1's mempool! Broadcasting failed"
    else
        echo "TX confirmed in node1 mempool"
    fi

    # Wait for transaction to propagate to mining node
    echo "Waiting for TX to propagate to mining node..."
    for i in {1..10}; do
        MEMPOOL=$($CLI2 getrawmempool 2>/dev/null)
        if echo "$MEMPOOL" | grep -q "$GOLD_REG"; then
            echo "TX confirmed in mining node mempool after ${i} seconds"
            break
        fi
        if [ $i -eq 10 ]; then
            echo "ERROR: TX not in mining node mempool after 10 seconds!"
            echo "Node connection status:"
            $CLI1 getpeerinfo | python3 -c "import sys, json; peers=json.load(sys.stdin); print(f'Node1 has {len(peers)} peers')"
            $CLI2 getpeerinfo | python3 -c "import sys, json; peers=json.load(sys.stdin); print(f'Node2 has {len(peers)} peers')"
        fi
        sleep 1
    done
else
    echo -e "${YELLOW}GOLD registration response: $GOLD_REG${NC}"
fi

# Mine block to confirm registration
echo "Mining block to confirm GOLD registration..."
$CLI2 -rpcwallet=miner generatetoaddress 1 "$MINER_ADDR" >/dev/null
sleep 2

# Verify GOLD is registered
GOLD_CHECK=$($CLI1 getassetpolicy "$GOLD_ID" 2>&1)
if echo "$GOLD_CHECK" | grep -q "icu_txid"; then
    echo "GOLD asset confirmed on chain"
else
    echo "Warning: GOLD asset not found after mining: $GOLD_CHECK"
fi

# Register SILVER asset
echo "Registering SILVER asset..."
SILVER_ICU=$($CLI1 -rpcwallet=test_wallet getnewaddress)
SILVER_REG=$($CLI1 -rpcwallet=test_wallet registerasset \
    "$SILVER_ICU" \
    5.1 \
    "$SILVER_ID" \
    3 \
    28 \
    510000000 \
    "SILVER" \
    6 \
    '{"autofund":true,"broadcast":true}' 2>&1)

if [[ "$SILVER_REG" =~ ^[a-f0-9]{64}$ ]]; then
    echo -e "${GREEN}SILVER registration TX: ${SILVER_REG:0:16}...${NC}"

    # Verify TX is in node1's mempool first
    NODE1_MEMPOOL=$($CLI1 getrawmempool 2>/dev/null)
    if ! echo "$NODE1_MEMPOOL" | grep -q "$SILVER_REG"; then
        echo "ERROR: TX not even in node1's mempool! Broadcasting failed"
    else
        echo "TX confirmed in node1 mempool"
    fi

    # Wait for transaction to propagate to mining node
    echo "Waiting for TX to propagate to mining node..."
    for i in {1..10}; do
        MEMPOOL=$($CLI2 getrawmempool 2>/dev/null)
        if echo "$MEMPOOL" | grep -q "$SILVER_REG"; then
            echo "TX confirmed in mining node mempool after ${i} seconds"
            break
        fi
        if [ $i -eq 10 ]; then
            echo "ERROR: TX not in mining node mempool after 10 seconds!"
        fi
        sleep 1
    done
else
    echo -e "${YELLOW}SILVER registration response: $SILVER_REG${NC}"
fi

# Mine block to confirm SILVER registration
echo "Mining block to confirm SILVER registration..."
$CLI2 -rpcwallet=miner generatetoaddress 1 "$MINER_ADDR" >/dev/null
sleep 2

# Verify SILVER is registered
SILVER_CHECK=$($CLI1 getassetpolicy "$SILVER_ID" 2>&1)
if echo "$SILVER_CHECK" | grep -q "icu_txid"; then
    echo "SILVER asset confirmed on chain"
else
    echo "Warning: SILVER asset not found after mining: $SILVER_CHECK"
fi

# Ensure nodes are synced
echo "Verifying nodes are synced..."
NODE1_HEIGHT=$($CLI1 getblockcount)
NODE2_HEIGHT=$($CLI2 getblockcount)
echo "Node1 height: $NODE1_HEIGHT, Node2 height: $NODE2_HEIGHT"

echo -e "${BLUE}Step 6: Mint assets${NC}"

# Get GOLD ICU details from policy
echo "Getting GOLD policy details..."
GOLD_POLICY=$($CLI1 getassetpolicy "$GOLD_ID" 2>/dev/null)
if [ -n "$GOLD_POLICY" ]; then
    ICU_TXID=$(echo "$GOLD_POLICY" | python3 -c "import sys, json; print(json.load(sys.stdin)['icu_txid'])")
    ICU_VOUT=$(echo "$GOLD_POLICY" | python3 -c "import sys, json; print(json.load(sys.stdin)['icu_vout'])")

    echo "GOLD ICU: txid=$ICU_TXID, vout=$ICU_VOUT"

    # Mint GOLD using proper API
    echo "Minting 10 GOLD..."
    MINT_ADDR=$($CLI1 -rpcwallet=test_wallet getnewaddress)
    NEW_ICU_ADDR=$($CLI1 -rpcwallet=test_wallet getnewaddress)

    GOLD_MINT=$($CLI1 -rpcwallet=test_wallet mintasset \
        "$ICU_TXID" \
        "$ICU_VOUT" \
        "$NEW_ICU_ADDR" \
        5.1 \
        "$MINT_ADDR" \
        0.001 \
        "$GOLD_ID" \
        1000000000 \
        3 \
        28 \
        510000000 \
        '{"autofund":true,"broadcast":true}' 2>&1 || echo "MINT_ERROR")

if [[ "$GOLD_MINT" =~ ^[a-f0-9]{64}$ ]]; then
    echo -e "${GREEN}GOLD mint TX: ${GOLD_MINT:0:16}...${NC}"
else
    echo -e "${YELLOW}GOLD mint response: $GOLD_MINT${NC}"
    echo "Continuing anyway..."
fi
else
    echo -e "${YELLOW}Could not get GOLD registration details${NC}"
fi

# Get SILVER ICU details from policy
echo "Getting SILVER policy details..."
SILVER_POLICY=$($CLI1 getassetpolicy "$SILVER_ID" 2>/dev/null)
if [ -n "$SILVER_POLICY" ]; then
    SILVER_ICU_TXID=$(echo "$SILVER_POLICY" | python3 -c "import sys, json; print(json.load(sys.stdin)['icu_txid'])")
    SILVER_ICU_VOUT=$(echo "$SILVER_POLICY" | python3 -c "import sys, json; print(json.load(sys.stdin)['icu_vout'])")

    echo "SILVER ICU: txid=$SILVER_ICU_TXID, vout=$SILVER_ICU_VOUT"

    # Mint SILVER using proper API
    echo "Minting 500 SILVER..."
    MINT_ADDR2=$($CLI1 -rpcwallet=test_wallet getnewaddress)
    NEW_ICU_ADDR2=$($CLI1 -rpcwallet=test_wallet getnewaddress)

    SILVER_MINT=$($CLI1 -rpcwallet=test_wallet mintasset \
        "$SILVER_ICU_TXID" \
        "$SILVER_ICU_VOUT" \
        "$NEW_ICU_ADDR2" \
        5.1 \
        "$MINT_ADDR2" \
        0.001 \
        "$SILVER_ID" \
        500000000 \
        3 \
        28 \
        510000000 \
        '{"autofund":true,"broadcast":true}' 2>&1 || echo "MINT_ERROR")

if [[ "$SILVER_MINT" =~ ^[a-f0-9]{64}$ ]]; then
    echo -e "${GREEN}SILVER mint TX: ${SILVER_MINT:0:16}...${NC}"
else
    echo -e "${YELLOW}SILVER mint response: $SILVER_MINT${NC}"
    echo "Continuing anyway..."
fi
else
    echo -e "${YELLOW}Could not get SILVER registration details${NC}"
fi

# Mine blocks to confirm mints
$CLI2 -rpcwallet=miner generatetoaddress 2 "$MINER_ADDR" >/dev/null
sleep 1

echo -e "${BLUE}Step 7: Check asset balances${NC}"

# Check asset balance
ASSET_BALANCE=$($CLI1 -rpcwallet=test_wallet getassetbalance 2>&1)
echo "Asset balances:"
echo "$ASSET_BALANCE"

# Check if we have known asset UTXOs (low-level check)
echo ""
echo "Checking for asset UTXOs (low-level):"
ASSET_UTXOS=$($CLI1 -rpcwallet=test_wallet listunspentassets 2>&1)
if echo "$ASSET_UTXOS" | grep -q "error"; then
    # Try alternative approach
    echo "Using listunspent to check for assets..."
    $CLI1 -rpcwallet=test_wallet listunspent | python3 -c "
import sys, json
utxos = json.load(sys.stdin)
asset_count = 0
for utxo in utxos:
    if 'assetid' in utxo or 'asset' in utxo:
        asset_count += 1
        print(f\"  Found asset UTXO: {utxo['txid'][:16]}...:{utxo['vout']}\")
if asset_count == 0:
    print('  No asset UTXOs found in wallet (this might be the bug)')
else:
    print(f'  Total asset UTXOs: {asset_count}')
" 2>/dev/null || echo "  Could not parse UTXOs"
else
    echo "$ASSET_UTXOS"
fi

# Stop node1 daemon so we can start the GUI
echo -e "${BLUE}Step 8: Stop node1 daemon (preparing for GUI)${NC}"
$CLI1 stop 2>/dev/null || true
sleep 3

# Make sure it's really stopped
pkill -f "bitcoind.*node1" 2>/dev/null || true
sleep 2

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Asset registration and minting complete!"
echo ""
echo "Registered assets:"
echo "  - GOLD (ID: ${GOLD_ID:0:16}...)"
echo "  - SILVER (ID: ${SILVER_ID:0:16}...)"
echo ""
echo "To start the GUI wallet:"
echo -e "${YELLOW}  DISPLAY=:1 ${BITCOIN_QT_BIN} -datadir=${GUI_DIR}/node1 -regtest -spv-asn-min=1${NC}"
echo ""
echo "To interact via CLI:"
echo "  Node1: $CLI1 -rpcwallet=test_wallet <command>"
echo "  Node2: $CLI2 -rpcwallet=miner <command>"
echo ""
echo "Mining node (node2) is still running in background (PID: $BITCOIND_PID)"

# Create a summary file for reference
cat > "${GUI_DIR}/asset_setup_summary.txt" <<EOF
Asset Setup Summary
==================

GOLD Asset:
  ID: $GOLD_ID
  Ticker: GOLD
  Decimals: 8
  Amount Minted: 10 GOLD (1000000000 units)
  ICU Address: $GOLD_ICU

SILVER Asset:
  ID: $SILVER_ID
  Ticker: SILVER
  Decimals: 6
  Amount Minted: 500 SILVER (500000000 units)
  ICU Address: $SILVER_ICU

Wallet Address: $TEST_ADDR
Mint Address: $MINT_ADDR

Node Configurations:
  Node1 (GUI): ${GUI_DIR}/node1
  Node2 (Mining): ${GUI_DIR}/node2

EOF

echo ""
echo "Asset setup details saved to: ${GUI_DIR}/asset_setup_summary.txt"