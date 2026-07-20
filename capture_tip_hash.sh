#!/bin/bash
# Script to capture TensorReg tip hash at height 100

echo "=== Capturing TensorReg tip hash at height 100 ==="

# Create a dedicated test directory
TEST_DIR="/tmp/tensorreg_tip_$(date +%s)"
mkdir -p "$TEST_DIR"

echo "Test directory: $TEST_DIR"

# Run only the validation_block_tests which uses TestChain100Setup
UNITTEST_CHAIN=tensor-reg ./build/bin/test_bitcoin \
    --run_test=validation_block_tests/processnewblock_signals_ordering \
    --log_level=all \
    -- -testdatadir="$TEST_DIR" 2>&1 | tee /tmp/tensor_test_output.log

# Look for the tip hash in debug.log
echo ""
echo "=== Searching for tip hash in logs ==="

# Find the debug.log file
DEBUG_LOG=$(find "$TEST_DIR" -name "debug.log" 2>/dev/null | head -1)

if [ -f "$DEBUG_LOG" ]; then
    echo "Found debug.log at: $DEBUG_LOG"
    echo ""
    echo "=== Chain tip information ==="
    grep -A2 -B2 "height=100" "$DEBUG_LOG" | tail -20
    echo ""
    echo "=== Looking for UpdateTip at height 100 ==="
    grep "UpdateTip.*height=100" "$DEBUG_LOG"
    echo ""
    echo "=== Last few blocks added ==="
    grep "UpdateTip" "$DEBUG_LOG" | tail -5
else
    echo "Debug.log not found. Checking test output..."
    grep -i "tip\|height=100\|hash" /tmp/tensor_test_output.log | grep -v "CheckBlock"
fi

# Also try running a simpler test that directly logs the tip
echo ""
echo "=== Running chainstate_write_tests to get chain info ==="
UNITTEST_CHAIN=tensor-reg ./build/bin/test_bitcoin \
    --run_test=chainstate_write_tests \
    --log_level=all 2>&1 | grep -E "tip|genesis|height" | head -20

echo ""
echo "=== Cleanup ==="
echo "Test directory preserved at: $TEST_DIR"
echo "Full output saved to: /tmp/tensor_test_output.log"