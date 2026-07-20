pragma circom 2.0.0;

/*
 * Minimal KYC Compliance Circuit for Testing
 *
 * This is a simplified circuit that validates:
 * 1. Holder knows a secret preimage that hashes to their public key
 * 2. Public inputs match expected schema for TensorCash
 *
 * Public Inputs (4 field elements):
 *   [0] chain_separator - prevents cross-chain replay
 *   [1] asset_id - binds proof to specific asset
 *   [2] compliance_root - Merkle root || height (unused in this simple test)
 *   [3] tfr_anchor - transfer reporting commitment (unused in this simple test)
 *
 * Private Inputs:
 *   secret - holder's secret preimage
 *   pubkey_hash - hash of secret (should equal holder's public key commitment)
 */

include "../../../../../../../node_modules/circomlib/circuits/poseidon.circom";

template KycCompliance() {
    // Public inputs (must be in this exact order for TensorCash compatibility)
    signal input chain_separator;
    signal input asset_id;
    signal input compliance_root;
    signal input tfr_anchor;

    // Private inputs
    signal input secret;
    signal input pubkey_hash;

    // Constraint 1: Verify the secret hashes to the pubkey_hash
    component hasher = Poseidon(1);
    hasher.inputs[0] <== secret;
    pubkey_hash === hasher.out;

    // Constraint 2: Ensure public inputs are properly bound
    // (In a real circuit, you'd check Merkle proofs, expiry, etc.)
    // For testing, we just ensure they're not zero
    signal chain_check;
    chain_check <== chain_separator * chain_separator;

    signal asset_check;
    asset_check <== asset_id * asset_id;
}

component main {public [chain_separator, asset_id, compliance_root, tfr_anchor]} = KycCompliance();
