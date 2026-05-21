package sw

// This file verifies the mathematical invariants underpinning the SW scheme.
// Each test documents the algebraic property it is checking and its role in
// protocol correctness.

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

var testP = func() *big.Int {
	p, _ := new(big.Int).SetString("340282366920938463463374607431768211507", 10)
	return p
}()

func randZP(t *testing.T, P *big.Int) *big.Int {
	t.Helper()
	v, err := rand.Int(rand.Reader, P)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	return v
}

// --- 1. Tag equation ---------------------------------------------------------

// TestTagEquation verifies the tag definition directly:
//
//	σ_i = PRF_K(i) mod P + Σ_{j=1}^S f_{i,j}·α_j  mod P
//
// TagBlocks must produce exactly this value for each block.
func TestTagEquation(t *testing.T) {
	P := testP
	params := &Params{S: 3, L: 2, P: P}

	k := make([]byte, 32)
	rand.Read(k)

	alpha := make([]*big.Int, params.S)
	for j := range params.S {
		alpha[j] = randZP(t, P)
	}
	sk := &SecretKey{K: k, Alpha: alpha, Params: params}

	block := make([]byte, 48) // 48 bytes / 3 sectors = 16 bytes per sector
	rand.Read(block)

	tags, err := TagBlocks(suite.SuiteV1, sk, blocks.NewMemStore([][]byte{block}))
	if err != nil {
		t.Fatal(err)
	}

	// Compute expected σ_0 directly.
	expected := new(big.Int).Mod(suite.SuiteV1.PRF(k, 0), P)
	for j := range params.S {
		fij := sectorElem(block, j, params.S, P)
		expected.Add(expected, new(big.Int).Mul(fij, alpha[j]))
		expected.Mod(expected, P)
	}

	if tags[0].Sigma.Cmp(expected) != 0 {
		t.Fatalf("tag σ_0 = %v, want %v", tags[0].Sigma, expected)
	}
}

// TestTagPRFDeterministic verifies that suite.SuiteV1.PRF(K, i) is deterministic:
// calling it twice with the same key and index yields the same value.
func TestTagPRFDeterministic(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)

	for _, i := range []int{0, 1, 99, 1000} {
		v1 := suite.SuiteV1.PRF(k, i)
		v2 := suite.SuiteV1.PRF(k, i)
		if v1.Cmp(v2) != 0 {
			t.Fatalf("PRF not deterministic at i=%d", i)
		}
	}
}

// TestTagPRFDistinct verifies that different block indices produce different
// PRF values with overwhelming probability.
func TestTagPRFDistinct(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)

	v0 := suite.SuiteV1.PRF(k, 0)
	v1 := suite.SuiteV1.PRF(k, 1)
	if v0.Cmp(v1) == 0 {
		t.Fatal("suite.SuiteV1.PRF(K, 0) == suite.SuiteV1.PRF(K, 1) — collision (negligible probability)")
	}
}

// --- 2. Sector extraction ----------------------------------------------------

// TestSectorElemPartition verifies that the S sectors partition the block:
// every byte of the block appears in exactly one sector.
func TestSectorElemPartition(t *testing.T) {
	P := testP
	s := 4
	block := make([]byte, 40) // 40 / 4 = 10 bytes per sector
	rand.Read(block)

	sectorSize := (len(block) + s - 1) / s
	for j := range s {
		start := j * sectorSize
		end := start + sectorSize
		if end > len(block) {
			end = len(block)
		}
		expected := new(big.Int).Mod(new(big.Int).SetBytes(block[start:end]), P)
		got := sectorElem(block, j, s, P)
		if got.Cmp(expected) != 0 {
			t.Fatalf("sectorElem sector %d: got %v, want %v", j, got, expected)
		}
	}
}

// TestSectorElemBeyondBlock verifies that a sector index past the end of the
// block returns 0 (zero-padding for short blocks).
func TestSectorElemBeyondBlock(t *testing.T) {
	P := testP
	block := make([]byte, 8)
	rand.Read(block)

	// With s=4, 8 bytes → 2 bytes per sector, so sectors 0-3 are valid.
	// sectorElem with j >= s is an invalid call in the protocol, but zero-padding
	// is the safe fallback if a block is shorter than expected.
	v := sectorElem(block, 10, 4, P) // way past end
	if v.Sign() != 0 {
		t.Fatalf("sectorElem past end: got %v, want 0", v)
	}
}

// TestSectorElemModP verifies that sectorElem reduces the sector value mod P.
func TestSectorElemModP(t *testing.T) {
	P := big.NewInt(7) // tiny prime so reduction is visible
	block := []byte{0xff, 0xff, 0xff, 0xff} // value 4294967295 > P
	v := sectorElem(block, 0, 1, P)
	if v.Cmp(new(big.Int).Mod(new(big.Int).SetBytes(block), P)) != 0 {
		t.Fatalf("sectorElem: not reduced mod P, got %v", v)
	}
	if v.Sign() < 0 || v.Cmp(P) >= 0 {
		t.Fatalf("sectorElem: %v not in [0, P)", v)
	}
}

// --- 3. Verification equation ------------------------------------------------

// TestVerificationEquation verifies the core algebraic identity at the field level:
//
//	σ == Σ_t ν_t·PRF_K(i_t) + Σ_j μ_j·α_j  mod P
//
// This is checked by constructing an honest proof manually and verifying that
// Verify accepts it, and then checking that the expanded equation holds.
func TestVerificationEquation(t *testing.T) {
	P := testP
	params := &Params{S: 3, L: 4, P: P}

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	file := make([][]byte, 10)
	for i := range file {
		b := make([]byte, 48)
		rand.Read(b)
		file[i] = b
	}
	tags, err := TagBlocks(suite.SuiteV1, sk, blocks.NewMemStore(file))
	if err != nil {
		t.Fatal(err)
	}

	chal, err := MakeChallenge(blocks.NewMemStore(file).IDs(), params)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := Respond(params, blocks.NewMemStore(file), tags, chal)
	if err != nil {
		t.Fatal(err)
	}

	// Check the equation manually.
	expected := big.NewInt(0)
	for t2, idx := range chal.Indices {
		nu := chal.Coeffs[t2]
		prf := new(big.Int).Mod(suite.SuiteV1.PRF(sk.K, idx), P)
		expected.Add(expected, new(big.Int).Mul(nu, prf))
		expected.Mod(expected, P)
	}
	for j := range params.S {
		expected.Add(expected, new(big.Int).Mul(proof.Mu[j], sk.Alpha[j]))
		expected.Mod(expected, P)
	}

	if proof.Sigma.Cmp(expected) != 0 {
		t.Fatalf("verification equation: proof.Sigma = %v, expected = %v", proof.Sigma, expected)
	}

	ok, err := Verify(suite.SuiteV1, sk, blocks.NewMemStore(file).IDs(), chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Verify rejected an honest proof")
	}
}

// TestVerificationEquationTamperedMu verifies that changing a μ_j value causes
// Verify to return false. μ_j encodes the file content; an adversary cannot
// produce a consistent μ_j for data it doesn't have.
func TestVerificationEquationTamperedMu(t *testing.T) {
	P := testP
	params := &Params{S: 3, L: 4, P: P}

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}
	file := make([][]byte, 10)
	for i := range file {
		b := make([]byte, 48)
		rand.Read(b)
		file[i] = b
	}
	tags, _ := TagBlocks(suite.SuiteV1, sk, blocks.NewMemStore(file))

	chal, _ := MakeChallenge(blocks.NewMemStore(file).IDs(), params)
	proof, _ := Respond(params, blocks.NewMemStore(file), tags, chal)

	// Flip one μ value.
	proof.Mu[0].Add(proof.Mu[0], big.NewInt(1))
	proof.Mu[0].Mod(proof.Mu[0], P)

	ok, err := Verify(suite.SuiteV1, sk, blocks.NewMemStore(file).IDs(), chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("Verify accepted a proof with a tampered μ value")
	}
}

// TestVerificationEquationTamperedSigma verifies that a modified Sigma is rejected.
func TestVerificationEquationTamperedSigma(t *testing.T) {
	P := testP
	params := &Params{S: 3, L: 4, P: P}

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}
	file := make([][]byte, 10)
	for i := range file {
		b := make([]byte, 48)
		rand.Read(b)
		file[i] = b
	}
	tags, _ := TagBlocks(suite.SuiteV1, sk, blocks.NewMemStore(file))

	chal, _ := MakeChallenge(blocks.NewMemStore(file).IDs(), params)
	proof, _ := Respond(params, blocks.NewMemStore(file), tags, chal)

	proof.Sigma.Add(proof.Sigma, big.NewInt(1))
	proof.Sigma.Mod(proof.Sigma, P)

	ok, err := Verify(suite.SuiteV1, sk, blocks.NewMemStore(file).IDs(), chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("Verify accepted a proof with a tampered Sigma")
	}
}

// --- 4. Challenge properties -------------------------------------------------

// TestMakeChallengeDistinctIndices verifies that all L indices in a challenge
// are distinct, as required by the Fisher-Yates partial shuffle.
func TestMakeChallengeDistinctIndices(t *testing.T) {
	P := testP
	params := &Params{S: 2, L: 10, P: P}

	for range 50 {
		chal, err := MakeChallenge(blocks.NewMemStore(make([][]byte, 20)).IDs(), params)
		if err != nil {
			t.Fatal(err)
		}
		seen := make(map[int]bool, len(chal.Indices))
		for _, idx := range chal.Indices {
			if seen[idx] {
				t.Fatalf("duplicate index %d in challenge", idx)
			}
			seen[idx] = true
		}
	}
}

// TestMakeChallengeIndicesInRange verifies that all challenge indices are in [0, n).
func TestMakeChallengeIndicesInRange(t *testing.T) {
	P := testP
	params := &Params{S: 2, L: 5, P: P}
	n := 15

	for range 30 {
		chal, err := MakeChallenge(blocks.NewMemStore(make([][]byte, n)).IDs(), params)
		if err != nil {
			t.Fatal(err)
		}
		for _, idx := range chal.Indices {
			if idx < 0 || idx >= n {
				t.Fatalf("index %d out of range [0, %d)", idx, n)
			}
		}
		if len(chal.Coeffs) != len(chal.Indices) {
			t.Fatalf("len(Coeffs)=%d != len(Indices)=%d", len(chal.Coeffs), len(chal.Indices))
		}
	}
}

// TestMakeChallengeCoeffsInZP verifies that all challenge coefficients are in Z_P.
func TestMakeChallengeCoeffsInZP(t *testing.T) {
	P := testP
	params := &Params{S: 2, L: 8, P: P}

	chal, err := MakeChallenge(blocks.NewMemStore(make([][]byte, 20)).IDs(), params)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range chal.Coeffs {
		if c.Sign() < 0 || c.Cmp(P) >= 0 {
			t.Fatalf("Coeffs[%d] = %v not in [0, P)", i, c)
		}
	}
}

// TestMakeChallengeNonDeterministic verifies that two challenges for the same
// parameters differ with overwhelming probability (fresh randomness each time).
func TestMakeChallengeNonDeterministic(t *testing.T) {
	P := testP
	params := &Params{S: 2, L: 5, P: P}

	c1, _ := MakeChallenge(blocks.NewMemStore(make([][]byte, 20)).IDs(), params)
	c2, _ := MakeChallenge(blocks.NewMemStore(make([][]byte, 20)).IDs(), params)

	same := true
	for i := range len(c1.Indices) {
		if c1.Indices[i] != c2.Indices[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two MakeChallenge calls produced identical indices (negligible probability)")
	}
}

// --- 5. Proof linearity ------------------------------------------------------

// TestProofSigmaLinearity verifies that the aggregated Sigma is linear in tags:
//
//	Σ_t ν_t · σ_{i_t} mod P
//
// For a single-element challenge {i_0, ν_0}, proof.Sigma must equal ν_0·σ_{i_0} mod P.
func TestProofSigmaLinearity(t *testing.T) {
	P := testP
	params := &Params{S: 2, L: 1, P: P} // single-block challenge

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}
	file := make([][]byte, 5)
	for i := range file {
		b := make([]byte, 32)
		rand.Read(b)
		file[i] = b
	}
	tags, err := TagBlocks(suite.SuiteV1, sk, blocks.NewMemStore(file))
	if err != nil {
		t.Fatal(err)
	}

	chal, err := MakeChallenge(blocks.NewMemStore(file).IDs(), params)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := Respond(params, blocks.NewMemStore(file), tags, chal)
	if err != nil {
		t.Fatal(err)
	}

	// For L=1: proof.Sigma == ν_0 * σ_{i_0} mod P.
	expected := new(big.Int).Mul(chal.Coeffs[0], tags[chal.Indices[0]].Sigma)
	expected.Mod(expected, P)

	if proof.Sigma.Cmp(expected) != 0 {
		t.Fatalf("single-element Sigma: got %v, want %v", proof.Sigma, expected)
	}
}

// TestProofMuLinearity verifies that Mu[j] = Σ_t ν_t · f_{i_t,j} mod P.
// For a single-element challenge, Mu[j] == ν_0 · f_{i_0,j}.
func TestProofMuLinearity(t *testing.T) {
	P := testP
	params := &Params{S: 3, L: 1, P: P}

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}
	file := make([][]byte, 5)
	for i := range file {
		b := make([]byte, 48)
		rand.Read(b)
		file[i] = b
	}
	tags, _ := TagBlocks(suite.SuiteV1, sk, blocks.NewMemStore(file))

	chal, _ := MakeChallenge(blocks.NewMemStore(file).IDs(), params)
	proof, _ := Respond(params, blocks.NewMemStore(file), tags, chal)

	idx := chal.Indices[0]
	nu := chal.Coeffs[0]
	for j := range params.S {
		fij := sectorElem(file[idx], j, params.S, P)
		expected := new(big.Int).Mul(nu, fij)
		expected.Mod(expected, P)
		if proof.Mu[j].Cmp(expected) != 0 {
			t.Fatalf("Mu[%d]: got %v, want %v", j, proof.Mu[j], expected)
		}
	}
}
