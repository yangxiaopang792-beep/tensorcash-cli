#!/bin/bash

set -euo pipefail

echo "=== Functional-Test Asset Environment Setup ==="

ROOT_DIR=/root
GUI_DIR=${ROOT_DIR}/tensorcash-test
TMP_ROOT=${ROOT_DIR}/tensorcash-functional
TEST_NAME=feature_assets_basic_highlevel
TEST_DIR=/build/bcore/test
CONFIG_FILE=${TEST_DIR}/config.ini

BITCOIND_BIN=/build/bcore/build/bin/bitcoind
BITCOINCLI_BIN=/build/bcore/build/bin/bitcoin-cli

TEST_RUNNER=/build/bcore/test/functional/test_runner.py

echo "Preparing temporary functional test directory: ${TMP_ROOT}" 
rm -rf "${TMP_ROOT}"
mkdir -p "${TMP_ROOT}"
mkdir -p "${TEST_DIR}"

if [ ! -f "${CONFIG_FILE}" ]; then
    cat >"${CONFIG_FILE}" <<CONFIG
[environment]
BUILDDIR=/build/bcore/build
SRCDIR=/build/bcore
EXEEXT=
CLIENT_NAME=Bitcoin Core
CLIENT_BUGREPORT=https://github.com/tensorcash/tensorcash/issues
[components]
ENABLE_WALLET=true
ENABLE_CLI=true
ENABLE_BITCOIND=true
ENABLE_ZMQ=true
ENABLE_EXTERNAL_SIGNER=true
CONFIG
fi

echo "Running functional test ${TEST_NAME} (with datadirs preserved)..."
echo "Using bitcoind: ${BITCOIND_BIN}"
echo "Using bitcoin-cli: ${BITCOINCLI_BIN}"
echo "Test directory: /build/bcore/test/functional"
echo "Temp directory: ${TMP_ROOT}"

cd /build/bcore/test/functional

# Check if test file exists
if [ ! -f "./${TEST_NAME}.py" ]; then
    echo "Error: Test file ${TEST_NAME}.py not found in $(pwd)" >&2
    ls -la feature_assets*.py 2>/dev/null || echo "No asset test files found"
    exit 1
fi

if ! BITCOIND="${BITCOIND_BIN}" BITCOINCLI="${BITCOINCLI_BIN}" \
    python3 ./test_runner.py "${TEST_NAME}" --nocleanup --tmpdir="${TMP_ROOT}"; then
    echo "Functional test failed; aborting setup." >&2
    # Show what was created even if test failed
    echo "Checking ${TMP_ROOT} for any created directories:"
    ls -la "${TMP_ROOT}" 2>/dev/null || echo "Temp directory not created"
    exit 1
fi

# The functional harness nests results as tmpdir/test_runner_xxx/${TEST_NAME}_0
RUN_DIR=$(ls -td "${TMP_ROOT}"/test_runner_* 2>/dev/null | head -n 1 || true)
if [ -z "${RUN_DIR}" ]; then
    echo "Could not locate test_runner output under ${TMP_ROOT}" >&2
    ls -R "${TMP_ROOT}" >&2 || true
    exit 1
fi

RESULT_DIR=$(ls -td "${RUN_DIR}/${TEST_NAME}_"* 2>/dev/null | head -n 1 || true)
if [ -z "${RESULT_DIR}" ]; then
    echo "Could not locate functional test datadir under ${RUN_DIR}" >&2
    ls -R "${RUN_DIR}" >&2 || true
    exit 1
fi

echo "Validating functional output before copying..."
CHECK_PORT=39654
CHECK_RPC=39653

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

# Force a full chainstate flush to ensure all registrations are on disk
echo "Forcing chainstate flush on node0..."
"${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} gettxoutsetinfo >/dev/null 2>&1 || true
sleep 2

if "${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} getblockcount >/dev/null 2>&1; then
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
        unregistered.append(asset_id)

if unregistered:
    print("Warning: the following assets had no registry entry saved in the functional output:")
    for asset_id in unregistered:
        print(f"  - {asset_id}")
    print("The GUI will mark them as unregistered.")
PY
    fi
fi

"${BITCOINCLI_BIN}" -datadir="${RESULT_DIR}/node0" -regtest -rpcport=${CHECK_RPC} stop >/dev/null 2>&1 || true

# Also sync node1's chainstate
echo "Forcing chainstate flush on node1..."
CHECK_PORT2=39664
CHECK_RPC2=39663
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

echo "Copying datadirs from ${RESULT_DIR} into ${GUI_DIR}"
rm -rf "${GUI_DIR}"
mkdir -p "${GUI_DIR}"

cp -a "${RESULT_DIR}/node0" "${GUI_DIR}/node1"
cp -a "${RESULT_DIR}/node1" "${GUI_DIR}/node2"

echo "Functional test environment ready."
echo "Node datadirs copied to ${GUI_DIR}/node1 and ${GUI_DIR}/node2"
echo "Use:"
echo "  bitcoind -datadir=${GUI_DIR}/node2 -regtest -daemon"
echo "  bitcoin-qt -datadir=${GUI_DIR}/node1 -regtest"
echo "to start the mining node and GUI wallet against confirmed asset balances."
