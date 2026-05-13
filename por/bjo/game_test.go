package bjo

import (
	"math/big"
	"testing"
)

// simpleFile creates n blocks of random 32-byte data.
func simpleFile(t *testing.T, n int) [][]byte {
	t.Helper()
	return randomBlocks(t, n, 32)
}

// TestPORChallengeGame runs the full POR protocol end-to-end:
// key generation, file encoding, challenge generation, server response,
// and client verification across all Q sentinels.
func TestPORChallengeGame(t *testing.T) {
	// §4.2.1 parameters: small values for test speed.
	// V=5 blocks per challenge, W=20 inner code width, Q=10 challenges,
	// (8,4) RS outer code. Production: V≈10, W≈100, Q≈1000, RS(255,223).
	params := &Params{
		V:      5,
		W:      20,
		Q:      10,
		P:      big.NewInt(2147483647), // 2^31-1, a Mersenne prime
		OuterN: 8,
		OuterK: 4,
	}

	// 1. KeyGen: client generates master key and all sub-keys.
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Encode: client applies SA-ECC and precomputes Q sentinel values.
	//    In a real deployment the client uploads ef to the server and deletes it.
	blocks := simpleFile(t, 100)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatal(err)
	}

	// The encoded file should contain the original blocks unchanged (systematic).
	for i, orig := range blocks {
		for b, v := range orig {
			if ef.Blocks[i][b] != v {
				t.Fatalf("encoded file not systematic at block %d byte %d", i, b)
			}
		}
	}

	// 3–5. For each challenge: client builds challenge, server responds, client verifies.
	for j := 1; j <= mk.Params.Q; j++ {
		chal, err := MakeChallenge(mk, j)
		if err != nil {
			t.Fatalf("MakeChallenge(j=%d): %v", j, err)
		}

		resp, err := Respond(ef, chal)
		if err != nil {
			t.Fatalf("Respond(j=%d): %v", j, err)
		}

		ok, err := Verify(mk, chal, resp)
		if err != nil {
			t.Fatalf("Verify(j=%d): %v", j, err)
		}
		if !ok {
			t.Fatalf("Verify(j=%d): valid proof rejected", j)
		}
	}
}

// TestPORTamperedBlockDetected verifies that a server that corrupts all stored
// blocks cannot produce a valid response: at least one of the Q challenges will
// detect the corruption.
func TestPORTamperedBlockDetected(t *testing.T) {
	params := &Params{
		V:      5,
		W:      20,
		Q:      10,
		P:      big.NewInt(2147483647),
		OuterN: 8,
		OuterK: 4,
	}

	mk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}

	blocks := simpleFile(t, 50)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt every block in the encoded file.
	for i := range ef.Blocks {
		ef.Blocks[i] = randomBlock(t, 32)
	}

	// With all blocks corrupted, at least one of the Q challenges must fail.
	anyFailed := false
	for j := 1; j <= mk.Params.Q; j++ {
		chal, _ := MakeChallenge(mk, j)
		resp, _ := Respond(ef, chal)
		ok, err := Verify(mk, chal, resp)
		if err != nil {
			t.Fatalf("Verify(j=%d): %v", j, err)
		}
		if !ok {
			anyFailed = true
		}
	}
	if !anyFailed {
		t.Fatal("all Q challenges passed despite all blocks being corrupted — soundness failure")
	}
}
