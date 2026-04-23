package pdp

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"
)

// simpleFile creates n blocks of random 1 KB data.
func simpleFile(t *testing.T, n int) [][]byte {
	t.Helper()
	blocks := make([][]byte, n)
	for i := range n {
		kbBlock := make([]byte, 1024)
		if _, err := rand.Read(kbBlock); err != nil {
			t.Fatal(err)
		}
		blocks[i] = kbBlock
	}
	return blocks
}

// TestPDPChallengeGame runs the full S-PDP protocol end-to-end:
// key generation, block tagging, challenge generation, server proof, and client verification.
func TestPDPChallengeGame(t *testing.T) {
	// 1. Setup: client generates key material.
	pk, sk, err := KeyGen(128) // small for test speed; use ≥1024 in production
	if err != nil {
		t.Fatal(err)
	}

	// 2. Client tags each block and would upload (blocks, tags) to the server.
	blocks := simpleFile(t, 1000)
	tags := make([]*Tag, len(blocks))
	for i := range blocks {
		w := binary.BigEndian.AppendUint64(append([]byte(nil), sk.V...), uint64(i))
		tags[i], err = SuiteV1.TagBlock(pk, sk, blocks[i], w)
		if err != nil {
			t.Fatal(err)
		}
	}

	// 3. Client generates a challenge.
	//    s is a per-challenge secret kept by the client; only g^s (Gs) is sent to the server.
	s, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		t.Fatal(err)
	}
	Gs := new(big.Int).Exp(pk.G, s, pk.N) // g^s, public blinding factor

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	if _, err = rand.Read(k1); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(k2); err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		SuiteID: SuiteV1.ID(),
		C:       4,
		K1:      k1,
		K2:      k2,
		Gs:      Gs,
	}

	// 4. Server generates proof from the blocks and tags.
	proof, err := SuiteV1.GenProof(pk, blocks, chal, tags)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Client verifies the proof using its private s.
	ok, err := SuiteV1.CheckProof(pk, sk, s, tags, chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("proof failed but should succeed")
	}
}
