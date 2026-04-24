package dagpdp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/pinionengineering/storage-proofs/pdp"
)

// simpleDAG creates n random 1 KB IPFS blocks and returns them together with
// a fetch function backed by a local in-memory store — standing in for a real
// IPFS pin store.
func simpleDAG(t *testing.T, n int) ([]blocks.Block, func(cid.Cid) ([]byte, error)) {
	t.Helper()
	blks := make([]blocks.Block, n)
	store := make(map[cid.Cid][]byte, n)
	for i := range n {
		data := make([]byte, 1024)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		b := blocks.NewBlock(data)
		blks[i] = b
		store[b.Cid()] = data
	}
	fetch := func(c cid.Cid) ([]byte, error) {
		data, ok := store[c]
		if !ok {
			return nil, fmt.Errorf("block not found: %s", c)
		}
		return data, nil
	}
	return blks, fetch
}

// newChallenge builds a random pdp.Challenge for the given suite and block count.
func newChallenge(t *testing.T, pk *pdp.PublicKey, c int) (*pdp.Challenge, *big.Int) {
	t.Helper()
	s, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		t.Fatal(err)
	}
	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	if _, err = rand.Read(k1); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(k2); err != nil {
		t.Fatal(err)
	}
	chal := &pdp.Challenge{
		SuiteID: pdp.SuiteV1.ID(),
		C:       c,
		K1:      k1,
		K2:      k2,
		Gs:      new(big.Int).Exp(pk.G, s, pk.N),
	}
	return chal, s
}

// TestDAGChallengeGame runs the full dagpdp protocol end-to-end:
// key generation, TagList construction, challenge, proof, and verification.
func TestDAGChallengeGame(t *testing.T) {
	pk, sk, err := pdp.KeyGen(128)
	if err != nil {
		t.Fatal(err)
	}

	blks, fetch := simpleDAG(t, 100)
	contentRoot := blks[0].Cid() // explicit root — not implied by position

	tagList, err := BuildTagList(pdp.SuiteV1, pk, sk, contentRoot, blks)
	if err != nil {
		t.Fatal(err)
	}
	if !tagList.ContentRoot.Equals(contentRoot) {
		t.Fatalf("ContentRoot mismatch: got %s, want %s", tagList.ContentRoot, contentRoot)
	}
	if len(tagList.Blocks) != len(blks) {
		t.Fatalf("TagList has %d blocks, want %d", len(tagList.Blocks), len(blks))
	}

	chal, s := newChallenge(t, pk, 4)

	proof, err := GenProof(tagList, pk, chal, fetch)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := CheckProof(tagList, pk, sk, s, chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("proof failed but should succeed")
	}
}

// TestDAGTamperedBlockFails confirms that a storage node returning corrupted
// block data produces a proof that CheckProof rejects.
func TestDAGTamperedBlockFails(t *testing.T) {
	pk, sk, err := pdp.KeyGen(128)
	if err != nil {
		t.Fatal(err)
	}

	blks, _ := simpleDAG(t, 100)
	tagList, err := BuildTagList(pdp.SuiteV1, pk, sk, blks[0].Cid(), blks)
	if err != nil {
		t.Fatal(err)
	}

	chal, s := newChallenge(t, pk, 4)

	// Fetch always returns fresh random garbage — simulating a node that has
	// lost or corrupted its pinned data.
	corruptFetch := func(_ cid.Cid) ([]byte, error) {
		garbage := make([]byte, 1024)
		rand.Read(garbage)
		return garbage, nil
	}

	proof, err := GenProof(tagList, pk, chal, corruptFetch)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := CheckProof(tagList, pk, sk, s, chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("proof should fail for corrupted blocks but succeeded")
	}
}

// TestDAGContentRootIsExplicit verifies that ContentRoot is set to exactly the
// CID passed to BuildTagList, regardless of which block appears first in blks.
func TestDAGContentRootIsExplicit(t *testing.T) {
	pk, sk, err := pdp.KeyGen(128)
	if err != nil {
		t.Fatal(err)
	}

	blks, _ := simpleDAG(t, 10)

	// Use a block that is not blks[0] as the declared content root.
	contentRoot := blks[5].Cid()
	tagList, err := BuildTagList(pdp.SuiteV1, pk, sk, contentRoot, blks)
	if err != nil {
		t.Fatal(err)
	}
	if !tagList.ContentRoot.Equals(contentRoot) {
		t.Fatalf("ContentRoot %s != declared root %s", tagList.ContentRoot, contentRoot)
	}
}
