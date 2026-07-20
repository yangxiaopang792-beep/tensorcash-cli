#!/usr/bin/env python3
"""
KYC Prover Service Integration for Functional Tests

Manages the kyc-prover service lifecycle for TensorCash functional tests.
"""

import os
import sys
import time
import subprocess
import requests
from typing import Tuple, Optional

# Add shared-utils to path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
KYC_PROVER_CLIENT_PATH = os.path.join(REPO_ROOT, "shared-utils", "kyc-prover", "pkg", "client", "python")
sys.path.insert(0, KYC_PROVER_CLIENT_PATH)

from kyc_prover import KYCProverClient, WitnessData


class KYCProverService:
    """Manages kyc-prover service for functional tests"""

    def __init__(self, port: int = 8080):
        self.port = port
        self.base_url = f"http://localhost:{port}"
        self.client = KYCProverClient(self.base_url)
        self.process: Optional[subprocess.Popen] = None
        self.prover_path = self._find_prover_binary()

    def _find_prover_binary(self) -> str:
        """Find the kyc-prover binary"""
        prover_dir = os.path.join(REPO_ROOT, "shared-utils", "kyc-prover")
        prover_bin = os.path.join(prover_dir, "kyc-prover")

        if not os.path.exists(prover_bin):
            raise FileNotFoundError(
                f"KYC prover binary not found at {prover_bin}. "
                f"Run: cd {prover_dir} && ./scripts/setup.sh"
            )

        return prover_bin

    def start(self):
        """Start the kyc-prover service"""
        if self.process is not None:
            print("KYC prover service already running")
            return

        print(f"Starting KYC prover service on port {self.port}...")

        # Find keys
        prover_dir = os.path.dirname(self.prover_path)
        pk_path = os.path.join(prover_dir, "proving_key.bin")
        vk_path = os.path.join(prover_dir, "verification_key.bin")

        if not os.path.exists(pk_path) or not os.path.exists(vk_path):
            raise FileNotFoundError(
                f"Proving keys not found. Run: cd {prover_dir} && ./scripts/setup.sh"
            )

        # Start service
        self.process = subprocess.Popen(
            [
                self.prover_path,
                "-port", str(self.port),
                "-pk", pk_path,
                "-vk", vk_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for service to be ready
        for i in range(30):  # 30 second timeout
            if self.client.health_check():
                print(f"✓ KYC prover service ready at {self.base_url}")
                return
            time.sleep(1)

        # Failed to start
        self.stop()
        raise RuntimeError("KYC prover service failed to start")

    def stop(self):
        """Stop the kyc-prover service"""
        if self.process is None:
            return

        print("Stopping KYC prover service...")
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

        self.process = None
        print("✓ KYC prover service stopped")

    def prove(
        self,
        chain_separator: str,
        asset_id: str,
        compliance_root: str,
        tfr_anchor: str,
        witness: WitnessData,
    ) -> Tuple[bytes, bytes]:
        """
        Generate a ZK proof.

        Returns:
            Tuple of (proof_bytes, public_inputs_bytes)
        """
        if not self.client.health_check():
            raise RuntimeError("KYC prover service is not running")

        proof_hex, inputs_hex = self.client.prove(
            chain_separator=chain_separator,
            asset_id=asset_id,
            compliance_root=compliance_root,
            tfr_anchor=tfr_anchor,
            witness=witness,
        )

        # Convert hex to bytes (strip 0x prefix)
        proof_bytes = bytes.fromhex(proof_hex[2:])
        inputs_bytes = bytes.fromhex(inputs_hex[2:])

        return proof_bytes, inputs_bytes

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()


# Helper to load golden vectors
def load_golden_vector(vector_name: str = "valid") -> Optional[dict]:
    """Load a pre-generated golden vector if available"""
    import json

    vectors_path = os.path.join(REPO_ROOT, "shared-utils", "kyc-prover", "vectors", "golden_vectors.json")

    if not os.path.exists(vectors_path):
        return None

    with open(vectors_path) as f:
        vectors = json.load(f)

    for v in vectors:
        if v["name"] == vector_name:
            return v

    return None


# Example usage in tests
if __name__ == "__main__":
    # Test the service
    with KYCProverService() as prover:
        # Load golden vector (REQUIRED)
        golden = load_golden_vector("valid")

        if not golden:
            print("✗ Golden vectors not found!")
            print("")
            print("Generate them with:")
            print("  cd shared-utils/kyc-prover")
            print("  ./scripts/generate_vectors.sh")
            print("")
            exit(1)

        print("✓ Using golden vector (VALID witness)")
        w = golden["witness"]
        witness = WitnessData(
            secret=w["secret"],
            pubkey_hash=w["pubkey_hash"],
            country=w["country"],
            age=w["age"],
            merkle_proof=w["merkle_proof"],
            merkle_index=w["merkle_index"],
            merkle_leaf_hash=w["merkle_leaf_hash"],
        )

        proof, inputs = prover.prove(
            chain_separator=w["chain_separator"],
            asset_id=w["asset_id"],
            compliance_root=w["compliance_root"],
            tfr_anchor=w["tfr_anchor"],
            witness=witness,
        )

        print(f"✓ Generated proof: {len(proof)} bytes")
        print(f"✓ Public inputs: {len(inputs)} bytes")
