package dagpor

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/pinionengineering/storage-proofs/por/bjo"
	"github.com/pinionengineering/storage-proofs/suite"
)

// defaultParams returns POR params suitable for tests with 32-byte blocks.
// P = 2^31-1 (Mersenne prime). Alpha = 0 skips Phase I extraction; the
// correctness requirement P > max(block value) is not needed for basic
// challenge/verify (only for extraction).
func defaultParams() *bjo.Params {
	return &bjo.Params{
		V:      5,
		W:      20,
		Q:      10,
		P:      big.NewInt(2147483647), // 2^31-1
		OuterN: 8,
		OuterK: 4,
	}
}

// simpleDAG creates n random blocks of size blockSize and returns them along
// with an in-memory block store pre-populated with all of them.
func simpleDAG(t *testing.T, n, blockSize int) ([]blocks.Block, map[cid.Cid][]byte) {
	t.Helper()
	blks := make([]blocks.Block, n)
	store := make(map[cid.Cid][]byte, n)
	for i := range n {
		data := make([]byte, blockSize)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		b := blocks.NewBlock(data)
		blks[i] = b
		store[b.Cid()] = data
	}
	return blks, store
}

// makeFetch returns a fetch function backed by store.
func makeFetch(store map[cid.Cid][]byte) func(cid.Cid) ([]byte, error) {
	return func(c cid.Cid) ([]byte, error) {
		data, ok := store[c]
		if !ok {
			return nil, fmt.Errorf("block not found: %s", c)
		}
		return data, nil
	}
}

// TestDAGChallengeGame runs the full dagpor protocol end-to-end:
// key generation, EncodedDAG construction, challenge, response, and verification.
func TestDAGChallengeGame(t *testing.T) {
	mk, err := bjo.KeyGen(defaultParams())
	if err != nil {
		t.Fatal(err)
	}

	blks, store := simpleDAG(t, 20, 32)
	contentRoot := blks[0].Cid()

	ed, parityBlks, err := BuildEncodedDAG(suite.SuiteV1, mk, contentRoot, blks)
	if err != nil {
		t.Fatal(err)
	}

	if !ed.ContentRoot.Equals(contentRoot) {
		t.Fatalf("ContentRoot mismatch: got %s, want %s", ed.ContentRoot, contentRoot)
	}
	if ed.NumMessage != len(blks) {
		t.Fatalf("NumMessage %d != %d", ed.NumMessage, len(blks))
	}

	// Add parity blocks to the store so Respond can fetch them.
	for _, pb := range parityBlks {
		store[pb.Cid()] = pb.RawData()
	}
	fetch := makeFetch(store)

	for j := 1; j <= mk.Params.Q; j++ {
		chal, err := bjo.MakeChallenge(mk, j)
		if err != nil {
			t.Fatalf("MakeChallenge(j=%d): %v", j, err)
		}

		resp, err := Respond(suite.SuiteV1, ed, chal, fetch)
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

// TestDAGTamperedBlockFails confirms that a storage node returning corrupted
// block data produces a response that Verify rejects for at least one challenge.
func TestDAGTamperedBlockFails(t *testing.T) {
	mk, err := bjo.KeyGen(defaultParams())
	if err != nil {
		t.Fatal(err)
	}

	blks, _ := simpleDAG(t, 20, 32)
	ed, _, err := BuildEncodedDAG(suite.SuiteV1, mk, blks[0].Cid(), blks)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch always returns fresh random garbage — simulating a node that has
	// lost or corrupted all its stored data.
	corruptFetch := func(_ cid.Cid) ([]byte, error) {
		garbage := make([]byte, 32)
		rand.Read(garbage)
		return garbage, nil
	}

	anyFailed := false
	for j := 1; j <= mk.Params.Q; j++ {
		chal, _ := bjo.MakeChallenge(mk, j)
		resp, err := Respond(suite.SuiteV1, ed, chal, corruptFetch)
		if err != nil {
			t.Fatalf("Respond(j=%d): %v", j, err)
		}
		ok, err := Verify(mk, chal, resp)
		if err != nil {
			t.Fatalf("Verify(j=%d): %v", j, err)
		}
		if !ok {
			anyFailed = true
		}
	}
	if !anyFailed {
		t.Fatal("all challenges passed despite all blocks being corrupted — soundness failure")
	}
}

// TestDAGContentRootIsExplicit verifies that ContentRoot is set to exactly the
// CID passed to BuildEncodedDAG, regardless of which block appears first in blks.
func TestDAGContentRootIsExplicit(t *testing.T) {
	mk, err := bjo.KeyGen(defaultParams())
	if err != nil {
		t.Fatal(err)
	}

	blks, _ := simpleDAG(t, 10, 32)

	// Use a block that is not blks[0] as the declared content root.
	contentRoot := blks[5].Cid()
	ed, _, err := BuildEncodedDAG(suite.SuiteV1, mk, contentRoot, blks)
	if err != nil {
		t.Fatal(err)
	}
	if !ed.ContentRoot.Equals(contentRoot) {
		t.Fatalf("ContentRoot %s != declared root %s", ed.ContentRoot, contentRoot)
	}
}

// TestDAGParityBlockCIDsMatch verifies that parity blocks returned by
// BuildEncodedDAG have CIDs that exactly match ed.Blocks[NumMessage:].
// This is the contract Respond relies on when fetching parity blocks.
func TestDAGParityBlockCIDsMatch(t *testing.T) {
	mk, err := bjo.KeyGen(defaultParams())
	if err != nil {
		t.Fatal(err)
	}

	blks, _ := simpleDAG(t, 12, 32)
	ed, parityBlks, err := BuildEncodedDAG(suite.SuiteV1, mk, blks[0].Cid(), blks)
	if err != nil {
		t.Fatal(err)
	}

	numParity := len(ed.Blocks) - ed.NumMessage
	if len(parityBlks) != numParity {
		t.Fatalf("parityBlks length %d != numParity %d", len(parityBlks), numParity)
	}

	for i, pb := range parityBlks {
		want := ed.Blocks[ed.NumMessage+i].CID
		if !pb.Cid().Equals(want) {
			t.Fatalf("parityBlks[%d].Cid() = %s, want %s", i, pb.Cid(), want)
		}
	}
}

// TestDAGOriginalBlockCIDsPreserved verifies that the original block CIDs in
// ed.Blocks[0:NumMessage] match the CIDs of the input blks slice.
// Respond uses these CIDs to fetch original blocks; they must not be recomputed.
func TestDAGOriginalBlockCIDsPreserved(t *testing.T) {
	mk, err := bjo.KeyGen(defaultParams())
	if err != nil {
		t.Fatal(err)
	}

	blks, _ := simpleDAG(t, 8, 32)
	ed, _, err := BuildEncodedDAG(suite.SuiteV1, mk, blks[0].Cid(), blks)
	if err != nil {
		t.Fatal(err)
	}

	for i, b := range blks {
		if !ed.Blocks[i].CID.Equals(b.Cid()) {
			t.Fatalf("ed.Blocks[%d].CID = %s, want %s", i, ed.Blocks[i].CID, b.Cid())
		}
	}
}
