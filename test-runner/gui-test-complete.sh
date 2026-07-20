#!/bin/bash

set -euo pipefail

echo "=== Complete GUI Testing Environment Setup ==="
echo ""

# Configuration
ROOT_DIR=/root
GUI_DIR=${ROOT_DIR}/tensorcash-test
BITCOIND_BIN=/build/bcore/build/bin/bitcoind
BITCOINCLI_BIN=/build/bcore/build/bin/bitcoin-cli
BITCOIN_QT_BIN=/build/bcore/build/bin/bitcoin-qt

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if we're in Docker
if [ ! -f /.dockerenv ]; then
    echo -e "${YELLOW}Warning: This script is designed to run inside the Docker container${NC}"
fi

# Function to check if VNC is running
check_vnc() {
    if xdpyinfo -display :1 >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to start VNC
start_vnc() {
    echo -e "${BLUE}Starting VNC server...${NC}"

    # Kill any existing VNC server
    vncserver -kill :1 2>/dev/null || true
    rm -rf /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true

    # Start VNC
    vncserver :1 -geometry 1280x800 -depth 24
    export DISPLAY=:1

    echo -e "${GREEN}VNC server started!${NC}"
    echo "Connect from your Mac using:"
    echo "  - Screen Sharing app: vnc://localhost:5901"
    echo "  - Or in Finder: Go → Connect to Server → vnc://localhost:5901"
    echo "  - Password: password"
    echo ""
}

# Parse command line arguments
RUN_MODE=${1:-"interactive"}  # interactive, auto, or vnc-only

case "$RUN_MODE" in
    "vnc-only")
        echo -e "${CYAN}Mode: VNC Only${NC}"
        start_vnc
        echo "VNC server is running. Start another terminal to continue setup."
        tail -f /dev/null
        exit 0
        ;;
    "auto")
        echo -e "${CYAN}Mode: Automatic (non-interactive)${NC}"
        ;;
    "interactive"|*)
        echo -e "${CYAN}Mode: Interactive${NC}"
        ;;
esac

# Step 1: Check/Start VNC if needed
if ! check_vnc; then
    echo -e "${YELLOW}VNC display :1 not found${NC}"
    read -p "Do you want to start VNC server now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_vnc
    else
        echo -e "${RED}Warning: GUI will not be visible without VNC${NC}"
    fi
else
    echo -e "${GREEN}VNC display :1 is already running${NC}"
fi

export DISPLAY=:1

# Step 2: Setup blockchain and assets
echo ""
echo -e "${BLUE}Setting up blockchain with assets...${NC}"

# Run the direct setup script (don't exit on failure)
if [ -f /setup-assets-direct.sh ]; then
    /setup-assets-direct.sh || echo "Setup script had issues but continuing..."
else
    echo -e "${RED}Error: /setup-assets-direct.sh not found${NC}"
    echo "Creating inline setup..."

    # Inline minimal setup if script not found
    CLI1="${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node1 -regtest -rpcuser=test -rpcpassword=test123"
    CLI2="${BITCOINCLI_BIN} -datadir=${GUI_DIR}/node2 -regtest -rpcuser=test -rpcpassword=test123 -rpcport=28443"

    # Kill existing processes
    pkill -f "bitcoind.*tensorcash-test" 2>/dev/null || true
    pkill -f "bitcoin-qt.*tensorcash-test" 2>/dev/null || true
    sleep 2

    # Setup directories
    rm -rf "${GUI_DIR}"
    mkdir -p "${GUI_DIR}/node1" "${GUI_DIR}/node2"

    # Create configs
    cat > "${GUI_DIR}/node1/bitcoin.conf" <<EOF
server=1
daemon=0
txindex=1
rpcuser=test
rpcpassword=test123
rpcallowip=127.0.0.1
[regtest]
port=18444
rpcport=18443
listen=1
assetsheight=1
fallbackfee=0.00001
EOF

    cat > "${GUI_DIR}/node2/bitcoin.conf" <<EOF
server=1
daemon=1
txindex=1
rpcuser=test
rpcpassword=test123
rpcallowip=127.0.0.1
[regtest]
port=28444
rpcport=28443
listen=1
connect=127.0.0.1:18444
assetsheight=1
fallbackfee=0.00001
EOF

    # Start mining node
    "${BITCOIND_BIN}" -datadir="${GUI_DIR}/node2" -regtest &
    BITCOIND_PID=$!
    sleep 5

    # Create wallets and mine blocks
    $CLI2 createwallet "miner" 2>/dev/null || true
    MINER_ADDR=$($CLI2 -rpcwallet=miner getnewaddress)
    $CLI2 -rpcwallet=miner generatetoaddress 150 "$MINER_ADDR" >/dev/null

    echo -e "${GREEN}Basic setup complete${NC}"
fi

# Step 3: Launch GUI
echo ""
echo -e "${BLUE}Launching Bitcoin-Qt GUI...${NC}"

# Make sure node1 daemon is stopped
${BITCOINCLI_BIN} -datadir="${GUI_DIR}/node1" -regtest stop 2>/dev/null || true
sleep 3

# Launch GUI
if [ -x "${BITCOIN_QT_BIN}" ]; then
    echo "Starting Bitcoin-Qt on display :1..."
    DISPLAY=:1 "${BITCOIN_QT_BIN}" \
        -datadir="${GUI_DIR}/node1" \
        -regtest \
        -spv-asn-min=1 \
        -fallbackfee=0.00001 \
        -printtoconsole &

    QT_PID=$!
    echo -e "${GREEN}Bitcoin-Qt started with PID: $QT_PID${NC}"

    # Wait a bit for GUI to initialize
    sleep 5

    # Create helper aliases file
    cat > /root/test-aliases.sh <<'EOF'
#!/bin/bash
alias tcli1="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node1 -regtest -rpcuser=test -rpcpassword=test123 -rpcwallet=test_wallet"
alias tcli2="/build/bcore/build/bin/bitcoin-cli -datadir=/root/tensorcash-test/node2 -regtest -rpcuser=test -rpcpassword=test123 -rpcport=28443 -rpcwallet=miner"
alias tmine="tcli2 generatetoaddress 1 \$(tcli2 getnewaddress)"
alias tbalance="echo 'Node1 BTC:'; tcli1 getbalance; echo 'Node1 Assets:'; tcli1 getassetbalance; echo 'Node2 BTC:'; tcli2 getbalance"

echo "Test aliases loaded:"
echo "  tcli1     - CLI for GUI wallet (node1)"
echo "  tcli2     - CLI for mining node (node2)"
echo "  tmine     - Mine one block"
echo "  tbalance  - Show all balances"
EOF
    chmod +x /root/test-aliases.sh

    echo ""
    echo -e "${GREEN}=== GUI Test Environment Ready ===${NC}"
    echo ""
    echo "The Bitcoin-Qt wallet should now be visible in your VNC session"
    echo ""
    echo -e "${CYAN}Quick Commands:${NC}"
    echo "  source /root/test-aliases.sh    # Load helpful aliases"
    echo "  tcli1 getassetbalance           # Check asset balances"
    echo "  tcli2 generatetoaddress 1 \$(tcli2 getnewaddress)  # Mine a block"
    echo ""
    echo -e "${CYAN}Test Scenarios:${NC}"
    echo "  1. Check Overview tab - should show BTC and asset balances"
    echo "  2. Go to Send tab - try sending assets"
    echo "  3. Check Transactions tab - view asset transactions"
    echo "  4. Use Receive tab - generate addresses for receiving assets"
    echo ""
    echo -e "${YELLOW}Known Issues:${NC}"
    echo "  - Wallet may not properly display asset-tagged UTXOs"
    echo "  - Use /wallet-asset-proof.sh to demonstrate the issue"
    echo "  - Use /workaround-lowlevel.sh for manual asset operations"
    echo ""

    if [ "$RUN_MODE" = "interactive" ]; then
        echo "Press Ctrl+C to stop the GUI and exit"
        wait $QT_PID
    fi
else
    echo -e "${RED}Error: bitcoin-qt not found at ${BITCOIN_QT_BIN}${NC}"
    exit 1
fi