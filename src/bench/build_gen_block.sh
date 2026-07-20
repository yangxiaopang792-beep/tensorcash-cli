#!/bin/bash
# Build script for gen_tensorcash_block utility

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BCORE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Building gen_tensorcash_block utility..."
echo "bcore directory: $BCORE_DIR"

# Try to find build directory
BUILD_DIR=""
for dir in "$BCORE_DIR/build" "$BCORE_DIR/build-debug" "$BCORE_DIR/build-release"; do
    if [ -d "$dir" ]; then
        BUILD_DIR="$dir"
        echo "Found build directory: $BUILD_DIR"
        break
    fi
done

if [ -z "$BUILD_DIR" ]; then
    echo "Error: Could not find build directory"
    echo "Please run cmake and build the project first"
    exit 1
fi

# Compile the generator
echo "Compiling gen_tensorcash_block..."

cd "$BUILD_DIR"

# Add the source to CMake and rebuild just this target
cat > "$BCORE_DIR/src/bench/gen_block_CMakeLists.txt.tmp" << 'EOF'
# Temporary CMakeLists for gen_tensorcash_block
add_executable(gen_tensorcash_block
    gen_tensorcash_block.cpp
)

target_link_libraries(gen_tensorcash_block
    core_interface
    test_util
    bitcoin_node
)
EOF

# Build using ninja or make
if command -v ninja &> /dev/null && [ -f build.ninja ]; then
    ninja src/bench/gen_tensorcash_block
elif [ -f Makefile ]; then
    make gen_tensorcash_block
else
    echo "Error: Neither ninja nor make found"
    exit 1
fi

echo ""
echo "Build complete! Executable: $BUILD_DIR/src/bench/gen_tensorcash_block"
