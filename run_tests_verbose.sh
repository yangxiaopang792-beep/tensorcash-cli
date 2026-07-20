#!/bin/bash
# Enhanced test runner with better error diagnostics

echo "=== TensorCash Test Runner with Enhanced Diagnostics ==="
echo "Date: $(date)"
echo "UNITTEST_CHAIN: ${UNITTEST_CHAIN:-not set}"
echo ""

# Function to run a test and capture detailed output
run_test() {
    local test_name=$1
    local output_file="/tmp/test_${test_name//\//_}.log"
    
    echo "Running: $test_name"
    
    # Run with maximum verbosity
    UNITTEST_CHAIN=tensor-reg ./build/bin/test_bitcoin \
        --run_test="$test_name" \
        --log_level=all \
        --report_level=detailed \
        --catch_system_errors=no \
        2>&1 | tee "$output_file"
    
    local exit_code=${PIPESTATUS[0]}
    
    if [ $exit_code -ne 0 ]; then
        echo "❌ FAILED: $test_name (exit code: $exit_code)"
        echo "   Error details:"
        
        # Extract assertion failures
        grep -A2 "Assertion.*failed" "$output_file" | head -10
        
        # Extract boost test errors
        grep "error: in" "$output_file" | head -5
        
        # Extract fatal errors
        grep "fatal error" "$output_file" | head -5
        
        # Check for specific common issues
        if grep -q "secp256k1_context_sign == nullptr" "$output_file"; then
            echo "   ⚠️  ECC context already initialized - likely test fixture conflict"
        fi
        
        if grep -q "InvalidChainFound.*Assertion.*tip" "$output_file"; then
            echo "   ⚠️  Chain tip is null - chain initialization failed"
        fi
        
        if grep -q "Unable to bind" "$output_file"; then
            echo "   ⚠️  Port binding failed - network configuration issue"
        fi
        
        echo "   Full log: $output_file"
        echo ""
        return 1
    else
        echo "✅ PASSED: $test_name"
        rm -f "$output_file"
        return 0
    fi
}

# Run specific problematic tests first
echo "=== Testing Known Problem Areas ==="
echo ""

run_test "key_io_tests/tensor_address_prefixes"
run_test "model_validation_tests/unregistered_model_rejected_on_tensorreg"
run_test "model_validation_tests/default_model_accepted_on_tensorreg"
# Skip TensorMain tests as they need proper chain setup
# run_test "model_validation_tests/tensormain_rejects_without_api"
# run_test "model_validation_tests/tensormain_accepts_with_full_green"

echo ""
echo "=== Running Full Test Suite ==="
echo ""

# Run all tests with summary
UNITTEST_CHAIN=tensor-reg ./build/bin/test_bitcoin \
    --log_level=test_suite \
    --report_level=short \
    2>&1 | tee /tmp/full_test_run.log

# Extract summary
echo ""
echo "=== Test Summary ==="
grep -E "test cases|failures|errors" /tmp/full_test_run.log

# Show any assertion failures
if grep -q "Assertion.*failed" /tmp/full_test_run.log; then
    echo ""
    echo "=== Assertion Failures Found ==="
    grep -B2 -A2 "Assertion.*failed" /tmp/full_test_run.log | head -20
fi

echo ""
echo "=== Common Issues and Solutions ==="
echo "1. ECC context errors: Test fixtures conflicting, run tests individually"
echo "2. Chain tip null: Chain not properly initialized for that chain type"
echo "3. Address prefix failures: Check chainparams.cpp for correct prefixes"
echo "4. Model validation failures: Ensure ModelDB is initialized"
echo ""
echo "Full test log: /tmp/full_test_run.log"