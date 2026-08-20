package capability

import (
	"crypto/rand"
	"testing"

	blockspkg "github.com/pinionengineering/storage-proofs/blocks"
)

const (
	sparseKeyBits         = 1024
	sparseChalSize        = 5
	sparseBlockSz         = 32
	sparseSectorsPerBlock = 4 // ceil(sparseBlockSz/sparseSectorsPerBlock)=8 bytes, well under MaxSWPubSectorBytes
)

func makeSparseStore(t *testing.T) *blockspkg.MapStore {
	t.Helper()
	addrs := []int{0, 100, 1000, 10000, 100000}
	ids := make([][]byte, len(addrs))
	data := make([][]byte, len(addrs))
	for i, addr := range addrs {
		ids[i] = blockspkg.IntID(addr)
		b := make([]byte, sparseBlockSz)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		data[i] = b
	}
	store, err := blockspkg.NewMapStore(ids, data)
	if err != nil {
		t.Fatalf("NewMapStore: %v", err)
	}
	return store
}

func trySparse(sch SchemeSpec, store blockspkg.BlockStore) (bool, error) {
	tagger, err := sch.NewTagger(sparseKeyBits, sparseChalSize, sparseBlockSz, sparseSectorsPerBlock)
	if err != nil {
		return false, err
	}
	if _, err = tagger.TagBlocks(store); err != nil {
		return false, err
	}
	encoded := tagger.EncodedBlocks()
	clientSetup, err := tagger.ClientSetup()
	if err != nil {
		return false, err
	}
	proverSetup, err := tagger.ProverSetup()
	if err != nil {
		return false, err
	}
	challenger, err := sch.ChalFactory.NewChallenger(clientSetup, sparseChalSize)
	if err != nil {
		return false, err
	}
	prover, err := sch.ProvFactory.NewProver(proverSetup, encoded)
	if err != nil {
		return false, err
	}
	chal, validator, err := challenger.Challenge(encoded.Len(), blockspkg.IDAtFunc(encoded))
	if err != nil {
		return false, err
	}
	proof, err := prover.Prove(chal, encoded)
	if err != nil {
		return false, err
	}
	return validator.Verify(chal, proof)
}

// TestSparseBlockSupport runs every scheme through a full protocol round
// against a store with non-sequential block IDs. Schemes declaring
// Cap.SparseBlocks = true must pass; others must not unexpectedly pass.
func TestSparseBlockSupport(t *testing.T) {
	store := makeSparseStore(t)
	for _, sch := range Schemes {
		sch := sch
		t.Run(sch.Name, func(t *testing.T) {
			ok, err := trySparse(sch, store)
			if sch.Cap.SparseBlocks {
				if err != nil {
					t.Errorf("protocol error: %v", err)
					return
				}
				if !ok {
					t.Errorf("verification failed on sparse store")
				}
			} else {
				if err == nil && ok {
					t.Errorf("unexpected pass: update Cap.SparseBlocks to true if this scheme now supports sparse stores")
				} else {
					t.Logf("expected failure: err=%v ok=%v", err, ok)
				}
			}
		})
	}
}
