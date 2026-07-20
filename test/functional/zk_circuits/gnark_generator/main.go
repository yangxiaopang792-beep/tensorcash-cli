package main

// Minimal / legacy test tooling: emits a small set of golden ZK vectors for the
// bcore functional tests. It is NOT the authoritative vector generator — production
// proving/verification vectors come from the kyc-prover generator. Some serialization
// paths here are placeholders (see TODOs below).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type TestVector struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Proof         string            `json:"proof_hex"`
	PublicInputs  string            `json:"public_inputs_hex"`
	VK            string            `json:"vk_hex"`
	ShouldPass    bool              `json:"should_pass"`
	ExpectedError string            `json:"expected_error,omitempty"`
	Witness       map[string]string `json:"witness"`
}

func main() {
	fmt.Println("=== TensorCash BLS12-381 Groth16 Test Vector Generator ===\n")

	// Step 1: Compile circuit
	fmt.Println("[1/6] Compiling circuit...")
	var circuit TensorCashKYCCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Circuit compiled: %d constraints\n\n", ccs.GetNbConstraints())

	// Step 2: Groth16 setup
	fmt.Println("[2/6] Running Groth16 setup (trusted setup)...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	fmt.Println("Setup complete\n")

	// Step 3: Serialize VK
	fmt.Println("[3/6] Serializing verification key...")
	vkBytes := serializeVK(vk)
	fmt.Printf("VK size: %d bytes\n\n", len(vkBytes))

	// Step 4: Generate test vectors
	vectors := []TestVector{}

	// Vector 1: Valid proof
	fmt.Println("[4/6] Generating Vector 1: Valid proof...")
	vec1 := generateValidVector(pk, vk, vkBytes, "valid_basic", map[string]*big.Int{
		"chain_separator": big.NewInt(123456789),
		"asset_id":        new(big.Int).SetBytes([]byte("deadbeef00000000000000000000000000000000000000000000000000000001")),
		"compliance_root": big.NewInt(1000),
		"tfr_anchor":      big.NewInt(0),
		"secret":          big.NewInt(42424242),
	})
	vectors = append(vectors, vec1)

	// Vector 2: Wrong asset_id (proof valid but for different asset)
	fmt.Println("[5/6] Generating Vector 2: Wrong asset_id...")
	vec2 := generateWrongAssetVector(pk, vk, vkBytes, "wrong_asset_id", map[string]*big.Int{
		"chain_separator":      big.NewInt(123456789),
		"asset_id_proof":       new(big.Int).SetBytes([]byte("deadbeef00000000000000000000000000000000000000000000000000000001")),
		"asset_id_transaction": new(big.Int).SetBytes([]byte("cafebabe00000000000000000000000000000000000000000000000000000001")),
		"compliance_root":      big.NewInt(1000),
		"tfr_anchor":           big.NewInt(0),
		"secret":               big.NewInt(42424242),
	})
	vectors = append(vectors, vec2)

	// Vector 3: Expired root (height too old)
	fmt.Println("[6/6] Generating Vector 3: Expired compliance root...")
	vec3 := generateValidVector(pk, vk, vkBytes, "expired_root", map[string]*big.Int{
		"chain_separator": big.NewInt(123456789),
		"asset_id":        new(big.Int).SetBytes([]byte("deadbeef00000000000000000000000000000000000000000000000000000001")),
		"compliance_root": big.NewInt(500), // Old height, would fail freshness check
		"tfr_anchor":      big.NewInt(0),
		"secret":          big.NewInt(42424242),
	})
	vec3.ShouldPass = false
	vec3.ExpectedError = "zk-epoch-stale"
	vec3.Description = "Compliance root too old (height 500 when current is 1000+)"
	vectors = append(vectors, vec3)

	// Write JSON output
	output, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic(err)
	}

	filename := "test_vectors.json"
	err = os.WriteFile(filename, output, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n✓ Generated %d test vectors\n", len(vectors))
	fmt.Printf("✓ Written to: %s\n\n", filename)

	// Print summary
	fmt.Println("Test Vectors Summary:")
	for i, vec := range vectors {
		status := "PASS"
		if !vec.ShouldPass {
			status = fmt.Sprintf("FAIL (%s)", vec.ExpectedError)
		}
		fmt.Printf("  %d. %s - %s\n", i+1, vec.Name, status)
	}
	fmt.Println("\nUse convert_vectors.py to convert to TensorCash format")
}

func generateValidVector(pk groth16.ProvingKey, vk groth16.VerifyingKey, vkBytes []byte, name string, inputs map[string]*big.Int) TestVector {
	// Compute pubkey_hash = MiMC(secret)
	secret := inputs["secret"]
	pubkeyHash := mimcHash(secret)

	// Create witness
	witness := TensorCashKYCCircuit{
		ChainSeparator: inputs["chain_separator"],
		AssetID:        inputs["asset_id"],
		ComplianceRoot: inputs["compliance_root"],
		TfrAnchor:      inputs["tfr_anchor"],
		Secret:         secret,
		PubkeyHash:     pubkeyHash,
	}

	// Generate proof
	fullWitness, _ := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	if err != nil {
		panic(err)
	}

	// Serialize proof and public inputs
	proofBytes := serializeProof(proof)
	publicInputs := serializePublicInputs([]frontend.Variable{
		witness.ChainSeparator,
		witness.AssetID,
		witness.ComplianceRoot,
		witness.TfrAnchor,
	})

	// Verify locally
	publicWitness, _ := fullWitness.Public()
	err = groth16.Verify(proof, vk, publicWitness)
	verified := err == nil

	return TestVector{
		Name:         name,
		Description:  "Valid KYC compliance proof",
		Proof:        hex.EncodeToString(proofBytes),
		PublicInputs: hex.EncodeToString(publicInputs),
		VK:           hex.EncodeToString(vkBytes),
		ShouldPass:   verified,
		Witness: map[string]string{
			"chain_separator": inputs["chain_separator"].String(),
			"asset_id":        hex.EncodeToString(inputs["asset_id"].Bytes()),
			"compliance_root": inputs["compliance_root"].String(),
			"tfr_anchor":      inputs["tfr_anchor"].String(),
			"secret":          inputs["secret"].String(),
		},
	}
}

func generateWrongAssetVector(pk groth16.ProvingKey, vk groth16.VerifyingKey, vkBytes []byte, name string, inputs map[string]*big.Int) TestVector {
	// Generate proof for asset_id_proof, but claim it's for asset_id_transaction
	secret := inputs["secret"]
	pubkeyHash := mimcHash(secret)

	witness := TensorCashKYCCircuit{
		ChainSeparator: inputs["chain_separator"],
		AssetID:        inputs["asset_id_proof"], // Proof is for this asset
		ComplianceRoot: inputs["compliance_root"],
		TfrAnchor:      inputs["tfr_anchor"],
		Secret:         secret,
		PubkeyHash:     pubkeyHash,
	}

	fullWitness, _ := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
	proof, _ := groth16.Prove(ccs, pk, fullWitness)

	proofBytes := serializeProof(proof)

	// But public inputs claim it's for asset_id_transaction (mismatch!)
	publicInputs := serializePublicInputs([]frontend.Variable{
		inputs["chain_separator"],
		inputs["asset_id_transaction"], // Different asset!
		inputs["compliance_root"],
		inputs["tfr_anchor"],
	})

	return TestVector{
		Name:          name,
		Description:   "Proof for asset A but claiming asset B",
		Proof:         hex.EncodeToString(proofBytes),
		PublicInputs:  hex.EncodeToString(publicInputs),
		VK:            hex.EncodeToString(vkBytes),
		ShouldPass:    false,
		ExpectedError: "zk-proof-bad",
		Witness: map[string]string{
			"chain_separator":      inputs["chain_separator"].String(),
			"asset_id_in_proof":    hex.EncodeToString(inputs["asset_id_proof"].Bytes()),
			"asset_id_in_tx":       hex.EncodeToString(inputs["asset_id_transaction"].Bytes()),
			"compliance_root":      inputs["compliance_root"].String(),
			"tfr_anchor":           inputs["tfr_anchor"].String(),
		},
	}
}

func serializeProof(proof groth16.Proof) []byte {
	// TODO: Implement BLS12-381 G1/G2 compressed point serialization
	// For now, return gnark's native serialization
	buf := make([]byte, 0)
	proof.WriteRawTo(&buf)
	return buf
}

func serializePublicInputs(inputs []frontend.Variable) []byte {
	// Each input is 32 bytes (BLS12-381 scalar field)
	result := make([]byte, len(inputs)*32)
	for i, input := range inputs {
		// Convert to big.Int and serialize
		val := input.(*big.Int)
		valBytes := val.Bytes()
		// Pad to 32 bytes
		copy(result[i*32+(32-len(valBytes)):], valBytes)
	}
	return result
}

func serializeVK(vk groth16.VerifyingKey) []byte {
	// TODO: Implement proper TensorCash VK format
	// For now, use gnark's serialization
	buf := make([]byte, 0)
	vk.WriteRawTo(&buf)
	return buf
}

func mimcHash(input *big.Int) *big.Int {
	// Simple MiMC hash implementation
	// In real circuit, this matches the gnark MiMC constraint
	return new(big.Int).Add(input, big.NewInt(1)) // Placeholder
}

var ccs frontend.CompiledConstraintSystem
