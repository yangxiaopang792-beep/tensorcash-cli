#!/usr/bin/env python3
"""
Generate Tensor-specific block filter test vectors.
This should be run against a TensorReg node to generate correct vectors.
"""

import json
import subprocess
import sys

def run_bitcoin_cli(cmd):
    """Run bitcoin-cli command and return JSON result"""
    result = subprocess.run(
        ["./build/bin/bitcoin-cli", "-regtest"] + cmd.split(),
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Error running command: {cmd}")
        print(result.stderr)
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip()

def generate_vectors():
    """Generate block filter vectors for TensorReg"""
    vectors = []
    
    # Start with genesis block
    blockhash = run_bitcoin_cli("getblockhash 0")
    if not blockhash:
        print("Failed to get genesis block hash")
        return
    
    prev_filter_header = "0000000000000000000000000000000000000000000000000000000000000000"
    
    # Generate vectors for first N blocks (adjust as needed)
    for height in range(0, 10):  # Start with first 10 blocks
        blockhash = run_bitcoin_cli(f"getblockhash {height}")
        if not blockhash:
            break
            
        block = run_bitcoin_cli(f"getblock {blockhash} 0")  # Get hex
        if not block:
            break
            
        # Get block filter
        filter_result = run_bitcoin_cli(f"getblockfilter {blockhash} basic")
        if not filter_result:
            print(f"No filter for block {height}, skipping...")
            continue
            
        # Build vector entry
        vector = [
            height,                                    # Block height
            blockhash,                                # Block hash  
            block,                                    # Block hex
            [],                                       # Previous outputs (empty for now)
            prev_filter_header,                       # Previous filter header
            filter_result.get("filter", ""),         # Filter
            filter_result.get("header", "")          # Filter header
        ]
        
        vectors.append(vector)
        prev_filter_header = filter_result.get("header", prev_filter_header)
        
        print(f"Generated vector for block {height}")
    
    return vectors

def write_header_file(vectors):
    """Write vectors to C++ header file"""
    
    header_content = """// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Generated TensorReg block filter test vectors
namespace json_tests {
static const char* blockfilters_tensor = R"(
"""
    
    header_content += json.dumps(vectors, indent=2)
    
    header_content += """
)";
} // namespace json_tests
"""
    
    with open("src/test/data/blockfilters_tensor.json.h", "w") as f:
        f.write(header_content)
    
    print(f"Written {len(vectors)} vectors to src/test/data/blockfilters_tensor.json.h")

if __name__ == "__main__":
    print("Generating Tensor block filter vectors...")
    print("Make sure you have a TensorReg node running with RPC enabled")
    
    vectors = generate_vectors()
    if vectors:
        write_header_file(vectors)
        print("Done!")
    else:
        print("Failed to generate vectors")
        sys.exit(1)