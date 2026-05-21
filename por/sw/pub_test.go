package sw

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

// --- helpers -----------------------------------------------------------------

func pubScheme(t *testing.T) *PubScheme {
	t.Helper()
	ps, err := NewPubScheme(4, 5)
	if err != nil {
		t.Fatalf("NewPubScheme: %v", err)
	}
	return ps
}

// --- 1. End-to-end game ------------------------------------------------------

// TestPubChallengeGame runs the full §3.3 protocol for 10 rounds:
// NewPubScheme, TagBlocks, MakeChallenge, RespondFetch, Verify.
// All rounds must pass on the same (alpha, pk, tags) triple.
func TestPubChallengeGame(t *testing.T) {
	ps := pubScheme(t)
	file := randomFile(t, 20, 32)

	store := blocks.NewMemStore(file)
	ids := store.IDs()
	tags, err := ps.TagBlocks(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != len(file) {
		t.Fatalf("TagBlocks returned %d tags, want %d", len(tags), len(file))
	}

	for round := range 10 {
		chal, err := ps.MakeChallenge(ids)
		if err != nil {
			t.Fatalf("MakeChallenge(round=%d): %v", round, err)
		}
		proof, err := ps.RespondFetch(tags, chal, store)
		if err != nil {
			t.Fatalf("RespondFetch(round=%d): %v", round, err)
		}
		ok, err := ps.Verify(chal, proof, ids)
		if err != nil {
			t.Fatalf("Verify(round=%d): %v", round, err)
		}
		if !ok {
			t.Fatalf("Verify(round=%d): valid proof rejected", round)
		}
	}
}

// --- 2. Public verifiability -------------------------------------------------

// TestVerifyPub verifies that anyone holding only the public key can verify
// a proof produced by the server — without access to the secret α.
func TestVerifyPub(t *testing.T) {
	ps := pubScheme(t)
	file := randomFile(t, 15, 32)

	store := blocks.NewMemStore(file)
	ids := store.IDs()
	tags, _ := ps.TagBlocks(store)
	chal, _ := ps.MakeChallenge(ids)
	proof, _ := ps.RespondFetch(tags, chal, store)

	pk := ps.PubKey()
	ok, err := VerifyPub(pk, chal, proof, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("VerifyPub rejected a valid proof")
	}
}

// TestVerifyPubTamperedMu verifies that modifying a μ_j value causes VerifyPub
// to reject the proof.
func TestVerifyPubTamperedMu(t *testing.T) {
	ps := pubScheme(t)
	file := randomFile(t, 15, 32)

	store := blocks.NewMemStore(file)
	ids := store.IDs()
	tags, _ := ps.TagBlocks(store)
	chal, _ := ps.MakeChallenge(ids)
	proof, _ := ps.RespondFetch(tags, chal, store)

	proof.Mu[0].Add(proof.Mu[0], big.NewInt(1))
	proof.Mu[0].Mod(proof.Mu[0], bn256.Order)

	ok, err := VerifyPub(ps.PubKey(), chal, proof, ids)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("VerifyPub accepted a proof with tampered μ₀")
	}
}

// TestVerifyPubTamperedSigma verifies that a G₁ sigma with a flipped bit is
// rejected. The sigma bytes are modified before verification.
func TestVerifyPubTamperedSigma(t *testing.T) {
	ps := pubScheme(t)
	file := randomFile(t, 15, 32)

	store := blocks.NewMemStore(file)
	ids := store.IDs()
	tags, _ := ps.TagBlocks(store)
	chal, _ := ps.MakeChallenge(ids)
	proof, _ := ps.RespondFetch(tags, chal, store)

	// Flip a byte in sigma — the result is (almost certainly) an invalid G₁
	// point, so Unmarshal will error. Verify must not accept it.
	proof.Sigma[3] ^= 0xff
	ok, err := VerifyPub(ps.PubKey(), chal, proof, ids)
	// Either Unmarshal errors or the pairing check fails — both are acceptable.
	if err == nil && ok {
		t.Fatal("VerifyPub accepted a proof with tampered sigma")
	}
}

// --- 3. Soundness ------------------------------------------------------------

// TestPubTamperedBlockFails verifies that a server returning random data for
// every block fails at least one of several challenges.
func TestPubTamperedBlockFails(t *testing.T) {
	ps := pubScheme(t)
	file := randomFile(t, 20, 32)
	store := blocks.NewMemStore(file)
	ids := store.IDs()
	tags, _ := ps.TagBlocks(store)

	anyFailed := false
	for range 10 {
		corruptBlocks := make([][]byte, len(file))
		for i := range corruptBlocks {
			g := make([]byte, 32)
			rand.Read(g)
			corruptBlocks[i] = g
		}
		chal, _ := ps.MakeChallenge(ids)
		proof, err := ps.RespondFetch(tags, chal, blocks.NewMemStore(corruptBlocks))
		if err != nil {
			t.Fatalf("RespondFetch: %v", err)
		}
		ok, err := ps.Verify(chal, proof, ids)
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

// --- 4. Scheme interface -----------------------------------------------------

// runScheme exercises the Scheme interface for any implementation: TagBlocks,
// MakeChallenge, RespondFetch, Verify across nRounds independent challenges.
func runScheme(t *testing.T, scheme Scheme, nBlocks, blockSize, nRounds int) {
	t.Helper()
	file := randomFile(t, nBlocks, blockSize)
	store := blocks.NewMemStore(file)

	tags, err := scheme.TagBlocks(store)
	if err != nil {
		t.Fatalf("TagBlocks: %v", err)
	}

	ids := store.IDs()
	for round := range nRounds {
		chal, err := scheme.MakeChallenge(ids)
		if err != nil {
			t.Fatalf("MakeChallenge(round=%d): %v", round, err)
		}
		proof, err := scheme.RespondFetch(tags, chal, store)
		if err != nil {
			t.Fatalf("RespondFetch(round=%d): %v", round, err)
		}
		ok, err := scheme.Verify(chal, proof, ids)
		if err != nil {
			t.Fatalf("Verify(round=%d): %v", round, err)
		}
		if !ok {
			t.Fatalf("Verify(round=%d): valid proof rejected", round)
		}
	}
}

// TestSchemeInterfacePriv runs the Scheme game through PrivScheme.
func TestSchemeInterfacePriv(t *testing.T) {
	priv, err := NewPrivScheme(suite.SuiteV1, smallParams())
	if err != nil {
		t.Fatal(err)
	}
	runScheme(t, priv, 20, 32, 5)
}

// TestSchemeInterfacePub runs the Scheme game through PubScheme.
func TestSchemeInterfacePub(t *testing.T) {
	pub, err := NewPubScheme(4, 5)
	if err != nil {
		t.Fatal(err)
	}
	runScheme(t, pub, 20, 32, 5)
}

// TestSchemeKind verifies that Kind() returns the correct discriminant.
func TestSchemeKind(t *testing.T) {
	priv, _ := NewPrivScheme(suite.SuiteV1, smallParams())
	if priv.Kind() != PrivKind {
		t.Fatalf("PrivScheme.Kind() = %v, want PrivKind", priv.Kind())
	}

	pub, _ := NewPubScheme(4, 5)
	if pub.Kind() != PubKind {
		t.Fatalf("PubScheme.Kind() = %v, want PubKind", pub.Kind())
	}
}

// --- 5. Small file -----------------------------------------------------------

// TestPubSmallFile verifies that PubScheme handles n < L by clamping L to n.
func TestPubSmallFile(t *testing.T) {
	ps, err := NewPubScheme(2, 10) // L=10 > n=3
	if err != nil {
		t.Fatal(err)
	}

	file := randomFile(t, 3, 32)
	store := blocks.NewMemStore(file)
	ids := store.IDs()
	tags, _ := ps.TagBlocks(store)

	chal, err := ps.MakeChallenge(ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(chal.Indices) != 3 {
		t.Fatalf("expected 3 challenge indices (clamped to n), got %d", len(chal.Indices))
	}

	proof, err := ps.RespondFetch(tags, chal, store)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ps.Verify(chal, proof, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Verify rejected a valid proof for small file")
	}
}
