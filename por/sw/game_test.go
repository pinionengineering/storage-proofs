package sw

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/pinionengineering/storage-proofs/pdp"
)

// smallParams returns SW params suitable for fast tests with 32-byte blocks.
// S=4 sectors of 8 bytes each; P is large enough that 2^64 < P.
func smallParams() *Params {
	// 2^127 - 1 is not prime; use a 128-bit prime.
	// For tests we just need P > 2^64 (8-byte sector values).
	p, _ := new(big.Int).SetString("340282366920938463463374607431768211507", 10) // 2^128 - 189, a prime
	return &Params{
		S: 4,
		L: 5,
		P: p,
	}
}

// randomFile creates n random blocks of size blockSize.
func randomFile(t *testing.T, n, blockSize int) [][]byte {
	t.Helper()
	blocks := make([][]byte, n)
	for i := range n {
		b := make([]byte, blockSize)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		blocks[i] = b
	}
	return blocks
}

// TestSWChallengeGame runs the full SW protocol end-to-end:
// KeyGen, TagFile, MakeChallenge, Respond, Verify across multiple rounds.
// SW supports unlimited audits — we run 20 rounds to confirm re-use.
func TestSWChallengeGame(t *testing.T) {
	params := smallParams()

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	file := randomFile(t, 50, 32)
	tags := TagFile(pdp.SuiteV1, sk, file)

	if len(tags) != len(file) {
		t.Fatalf("TagFile returned %d tags, want %d", len(tags), len(file))
	}

	for round := range 20 {
		chal, err := MakeChallenge(len(file), params)
		if err != nil {
			t.Fatalf("MakeChallenge(round=%d): %v", round, err)
		}

		proof, err := Respond(params, file, tags, chal)
		if err != nil {
			t.Fatalf("Respond(round=%d): %v", round, err)
		}

		ok, err := Verify(pdp.SuiteV1, sk, chal, proof)
		if err != nil {
			t.Fatalf("Verify(round=%d): %v", round, err)
		}
		if !ok {
			t.Fatalf("Verify(round=%d): valid proof rejected", round)
		}
	}
}

// TestSWTamperedBlockFails verifies that a server returning random data for
// every block fails verification on at least one of several challenges.
func TestSWTamperedBlockFails(t *testing.T) {
	params := smallParams()

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	file := randomFile(t, 30, 32)
	tags := TagFile(pdp.SuiteV1, sk, file)

	// Corrupt fetch: always return fresh random data.
	corruptFetch := func(_ int) ([]byte, error) {
		garbage := make([]byte, 32)
		rand.Read(garbage)
		return garbage, nil
	}

	anyFailed := false
	for range 20 {
		chal, _ := MakeChallenge(len(file), params)
		proof, err := RespondFetch(params, tags, chal, corruptFetch)
		if err != nil {
			t.Fatalf("RespondFetch: %v", err)
		}
		ok, err := Verify(pdp.SuiteV1, sk, chal, proof)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !ok {
			anyFailed = true
		}
	}
	if !anyFailed {
		t.Fatal("all challenges passed despite all blocks corrupted — soundness failure")
	}
}

// TestSWUnlimitedChallenges verifies that SW truly supports unlimited audits:
// 100 independent challenges all pass on the same (sk, tags) pair.
// In contrast, BJO consumes one sentinel per challenge and is bounded by Q.
func TestSWUnlimitedChallenges(t *testing.T) {
	params := smallParams()

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	file := randomFile(t, 20, 32)
	tags := TagFile(pdp.SuiteV1, sk, file)

	for round := range 100 {
		chal, err := MakeChallenge(len(file), params)
		if err != nil {
			t.Fatalf("MakeChallenge(round=%d): %v", round, err)
		}
		proof, err := Respond(params, file, tags, chal)
		if err != nil {
			t.Fatalf("Respond(round=%d): %v", round, err)
		}
		ok, err := Verify(pdp.SuiteV1, sk, chal, proof)
		if err != nil {
			t.Fatalf("Verify(round=%d): %v", round, err)
		}
		if !ok {
			t.Fatalf("Verify(round=%d): valid proof rejected at round %d", round, round)
		}
	}
}

// TestSWRespondFetchEquivalent verifies that RespondFetch and Respond produce
// identical proofs when given the same file data.
func TestSWRespondFetchEquivalent(t *testing.T) {
	params := smallParams()

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	file := randomFile(t, 15, 32)
	tags := TagFile(pdp.SuiteV1, sk, file)

	chal, err := MakeChallenge(len(file), params)
	if err != nil {
		t.Fatal(err)
	}

	p1, err := Respond(params, file, tags, chal)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := RespondFetch(params, tags, chal, func(idx int) ([]byte, error) {
		return file[idx], nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if p1.Sigma.Cmp(p2.Sigma) != 0 {
		t.Fatal("Respond and RespondFetch produced different Sigma")
	}
	for j := range params.S {
		if p1.Mu[j].Cmp(p2.Mu[j]) != 0 {
			t.Fatalf("Respond and RespondFetch differ at Mu[%d]", j)
		}
	}
}

// TestSWSmallFile verifies the protocol works when n < L (fewer blocks than
// challenge size); MakeChallenge clamps L to n.
func TestSWSmallFile(t *testing.T) {
	params := &Params{
		S: 2,
		L: 10, // L deliberately larger than file
		P: smallParams().P,
	}

	sk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	file := randomFile(t, 3, 32) // only 3 blocks
	tags := TagFile(pdp.SuiteV1, sk, file)

	chal, err := MakeChallenge(len(file), params)
	if err != nil {
		t.Fatal(err)
	}
	if len(chal.Indices) != 3 {
		t.Fatalf("expected 3 indices (clamped to n), got %d", len(chal.Indices))
	}

	proof, err := Respond(params, file, tags, chal)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := Verify(pdp.SuiteV1, sk, chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Verify rejected valid proof for small file")
	}
}
