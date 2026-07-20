#!/bin/bash

set -uo pipefail

ROOT_DIR=/root
GUI_DIR=${ROOT_DIR}/tensorcash-test
BITCOINCLI_BIN=/build/bcore/build/bin/bitcoin-cli
STATE_FILE=/tmp/gui-assets-state.env

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

wait_for_bitcoind_shutdown() {
    local datadir="$1"
    local timeout="${2:-60}"
    local elapsed=0
    local pidfile="${datadir}/regtest/bitcoind.pid"

    while [ "${elapsed}" -lt "${timeout}" ]; do
        if [ ! -f "${pidfile}" ]; then
            if ! pgrep -f "bitcoind.*${datadir}" >/dev/null 2>&1; then
                return 0
            fi
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo -e "${YELLOW}Warning: Timed out waiting for bitcoind shutdown in ${datadir}${NC}" >&2
    return 1
}

QT_PID=""
MINING_PID=""
VNC_STARTED=0

if [ -f "${STATE_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
fi

echo -e "${GREEN}Stopping TensorCash GUI environment...${NC}"

if [ -n "${MINING_PID}" ] && kill -0 "${MINING_PID}" 2>/dev/null; then
    echo "  - stopping background mining loop"
    kill "${MINING_PID}" >/dev/null 2>&1 || true
    for _ in {1..10}; do
        if ! kill -0 "${MINING_PID}" 2>/dev/null; then
            break
        fi
        sleep 1
    done
fi

echo "  - shutting down mining node (node2)"
"${BITCOINCLI_BIN}" -datadir="${GUI_DIR}/node2" -regtest -rpcport=28443 stop >/dev/null 2>&1 || true
wait_for_bitcoind_shutdown "${GUI_DIR}/node2" 120 || true

echo "  - shutting down wallet node (node1)"
"${BITCOINCLI_BIN}" -datadir="${GUI_DIR}/node1" -regtest stop >/dev/null 2>&1 || true
wait_for_bitcoind_shutdown "${GUI_DIR}/node1" 120 || true

if [ -n "${QT_PID}" ] && kill -0 "${QT_PID}" 2>/dev/null; then
    echo "  - waiting for GUI process to exit"
    for _ in {1..10}; do
        if ! kill -0 "${QT_PID}" 2>/dev/null; then
            break
        fi
        sleep 1
    done
fi

if [ "${VNC_STARTED}" -eq 1 ]; then
    echo "  - stopping VNC server"
    vncserver -kill :1 >/dev/null 2>&1 || true
fi

rm -f "${STATE_FILE}" 2>/dev/null || true

echo -e "${GREEN}Cleanup complete. Datadirs in ${GUI_DIR} are safe to copy.${NC}"
