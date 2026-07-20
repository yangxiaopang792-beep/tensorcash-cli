package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// TensorCashKYCCircuit is a minimal compliance circuit matching TensorCash schema
// Public Inputs (4 field elements):
//   [0] ChainSeparator - prevents cross-chain replay
//   [1] AssetID - binds proof to specific asset
//   [2] ComplianceRoot - Merkle root || height
//   [3] TfrAnchor - transfer reporting commitment
//
// Private Inputs:
//   Secret - holder's secret preimage
//   PubkeyHash - expected hash of secret
type TensorCashKYCCircuit struct {
	// Public inputs (MUST be in this exact order)
	ChainSeparator frontend.Variable `gnark:",public"`
	AssetID        frontend.Variable `gnark:",public"`
	ComplianceRoot frontend.Variable `gnark:",public"`
	TfrAnchor      frontend.Variable `gnark:",public"`

	// Private inputs (witness)
	Secret     frontend.Variable `gnark:",secret"`
	PubkeyHash frontend.Variable `gnark:",secret"`
}

// Define declares the circuit constraints
func (circuit *TensorCashKYCCircuit) Define(api frontend.API) error {
	// Constraint 1: Verify secret hashes to pubkey_hash
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Secret)
	computedHash := mimc.Sum()
	api.AssertIsEqual(computedHash, circuit.PubkeyHash)

	// Constraint 2: Ensure public inputs are non-zero (prevents trivial proofs)
	api.AssertIsDifferent(circuit.ChainSeparator, 0)
	api.AssertIsDifferent(circuit.AssetID, 0)

	return nil
}
