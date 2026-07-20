module tensorcash/zktest

go 1.21

// This generator intentionally uses UPSTREAM consensys/gnark, NOT the
// tensorcash/gnark v0.9.1-plain-rangecheck fork. Its circuit uses only
// frontend + std/hash/mimc (never std/math/emulated or std/rangecheck), so the
// rangecheck patch the HD/HDv1 prover requires does not apply here.
// Run `go mod tidy` to produce go.sum before building.
require (
	github.com/consensys/gnark v0.9.1
	github.com/consensys/gnark-crypto v0.12.1
)
