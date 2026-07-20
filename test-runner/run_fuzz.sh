#!/bin/bash
#
# TensorCash Fuzz Test Runner Script
# This script manages fuzz testing in the Docker environment
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
FUZZ_DIR="/build/bcore"
BUILD_DIR="${FUZZ_DIR}/build_fuzz"
FUZZ_BINARY="${BUILD_DIR}/bin/fuzz"
CORPUS_DIR="${FUZZ_DIR}/fuzz_corpora"
OUTPUT_DIR="${FUZZ_DIR}/fuzz_outputs"

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS] [FUZZ_TARGET]"
    echo ""
    echo "Options:"
    echo "  -h, --help         Show this help message"
    echo "  -l, --list         List available fuzz targets"
    echo "  -r, --runs NUM     Number of fuzzing runs (default: 1000)"
    echo "  -t, --timeout SEC  Timeout in seconds (default: 60)"
    echo "  -a, --all          Run all fuzz targets"
    echo "  -c, --clean        Clean output directories before running"
    echo ""
    echo "Environment Variables:"
    echo "  FUZZ              The fuzz target to run"
    echo "  FUZZ_RUNS         Number of runs"
    echo "  FUZZ_TIMEOUT      Timeout in seconds"
    echo ""
    echo "Examples:"
    echo "  $0 process_message"
    echo "  $0 --all --runs 100"
    echo "  FUZZ=block_header $0"
}

# Check if fuzz binary exists
check_fuzz_binary() {
    if [ ! -x "${FUZZ_BINARY}" ]; then
        print_msg $RED "ERROR: Fuzz binary not found at ${FUZZ_BINARY}"
        print_msg $YELLOW "Please rebuild with fuzz support enabled"
        return 1
    fi
    print_msg $GREEN "✓ Fuzz binary found"
}

# List available fuzz targets
list_targets() {
    print_msg $GREEN "Available fuzz targets:"
    echo ""

    # List cpp files in src/test/fuzz
    if [ -d "${FUZZ_DIR}/src/test/fuzz" ]; then
        for file in ${FUZZ_DIR}/src/test/fuzz/*.cpp; do
            if [ -f "$file" ]; then
                basename "$file" .cpp | grep -v "^fuzz$" | grep -v "^util$"
            fi
        done | sort | column -c 80
    else
        print_msg $RED "Fuzz test directory not found"
    fi
}

# Run a single fuzz target
run_fuzz_target() {
    local target=$1
    local runs=${2:-1000}
    local timeout=${3:-60}

    print_msg $GREEN "Running fuzz target: ${target}"
    print_msg $YELLOW "Runs: ${runs}, Timeout: ${timeout}s"

    # Create directories if they don't exist
    mkdir -p "${CORPUS_DIR}/${target}"
    mkdir -p "${OUTPUT_DIR}/${target}"

    # Set environment and run
    export FUZZ="${target}"

    # Run with timeout
    timeout "${timeout}" "${FUZZ_BINARY}" \
        -runs="${runs}" \
        "${CORPUS_DIR}/${target}" \
        2>&1 | tee "${OUTPUT_DIR}/${target}/output.log" || {
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_msg $YELLOW "Fuzzing timed out after ${timeout} seconds"
        else
            print_msg $RED "Fuzzing failed with exit code: $exit_code"
            return $exit_code
        fi
    }

    # Check for crashes
    if [ -f "${OUTPUT_DIR}/${target}/crash-"* ]; then
        print_msg $RED "⚠ Crashes detected for ${target}!"
        ls -la "${OUTPUT_DIR}/${target}/crash-"*
    else
        print_msg $GREEN "✓ No crashes detected for ${target}"
    fi
}

# Run all fuzz targets
run_all_targets() {
    local runs=${1:-100}
    local timeout=${2:-30}

    print_msg $GREEN "Running all fuzz targets..."

    local targets=$(list_targets | tail -n +3)  # Skip header lines
    local total=$(echo "$targets" | wc -w)
    local current=0
    local failed=0

    for target in $targets; do
        current=$((current + 1))
        print_msg $YELLOW "\n[$current/$total] Testing: ${target}"

        if run_fuzz_target "$target" "$runs" "$timeout"; then
            print_msg $GREEN "✓ ${target} completed"
        else
            print_msg $RED "✗ ${target} failed"
            failed=$((failed + 1))
        fi
    done

    print_msg $GREEN "\n=== Summary ==="
    print_msg $GREEN "Total: $total, Failed: $failed"

    return $failed
}

# Clean output directories
clean_outputs() {
    print_msg $YELLOW "Cleaning output directories..."
    rm -rf "${OUTPUT_DIR}"/*
    print_msg $GREEN "✓ Cleaned"
}

# Main execution
main() {
    local target=""
    local runs=1000
    local timeout=60
    local run_all=false
    local clean=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -l|--list)
                list_targets
                exit 0
                ;;
            -r|--runs)
                runs="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -a|--all)
                run_all=true
                shift
                ;;
            -c|--clean)
                clean=true
                shift
                ;;
            *)
                target="$1"
                shift
                ;;
        esac
    done

    # Check environment variables
    [ -n "$FUZZ_RUNS" ] && runs="$FUZZ_RUNS"
    [ -n "$FUZZ_TIMEOUT" ] && timeout="$FUZZ_TIMEOUT"
    [ -n "$FUZZ" ] && target="$FUZZ"

    print_msg $GREEN "=== TensorCash Fuzz Testing ==="

    # Check binary
    check_fuzz_binary || exit 1

    # Clean if requested
    if [ "$clean" = true ]; then
        clean_outputs
    fi

    # Run tests
    if [ "$run_all" = true ]; then
        run_all_targets "$runs" "$timeout"
    elif [ -n "$target" ]; then
        run_fuzz_target "$target" "$runs" "$timeout"
    else
        print_msg $YELLOW "No target specified. Use -h for help."
        echo ""
        list_targets
    fi
}

# Run main function
main "$@"