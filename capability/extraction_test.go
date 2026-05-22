package capability

import (
	"bytes"
	"crypto/rand"
	"testing"

	blockspkg "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
)

const (
	extractKeyBits  = 128
	extractChalSize = 5
	extractNBlocks  = 20
	extractBlockSz  = 32
)

func makeExtractStore(t *testing.T) *blockspkg.MemStore {
	t.Helper()
	blks := make([][]byte, extractNBlocks)
	for i := range blks {
		blks[i] = make([]byte, extractBlockSz)
		if _, err := rand.Read(blks[i]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	}
	return blockspkg.NewMemStore(blks)
}

func tryExtraction(sch SchemeSpec, original blockspkg.BlockStore) (bool, error) {
	tagger, err := sch.NewTagger(extractKeyBits, extractChalSize)
	if err != nil {
		return false, err
	}
	if _, err = tagger.TagBlocks(original); err != nil {
		return false, err
	}

	ep, ok := tagger.(line.ExtractorProducer)
	if !ok {
		return false, nil
	}
	extractor, err := ep.NewExtractor()
	if err != nil {
		return false, err
	}

	recovered, err := extractor.Extract(tagger.EncodedBlocks())
	if err != nil {
		return false, err
	}

	if recovered.Len() != original.Len() {
		return false, nil
	}
	for i := range original.Len() {
		orig, err := blockspkg.BlockAt(original, i)
		if err != nil {
			return false, err
		}
		rec, err := blockspkg.BlockAt(recovered, i)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(orig, rec) {
			return false, nil
		}
	}
	return true, nil
}

// TestExtractionSupport runs every scheme through tag → extract and verifies
// that schemes declaring Cap.Extraction = true correctly recover the original
// blocks. Schemes that do not declare support must not unexpectedly succeed.
func TestExtractionSupport(t *testing.T) {
	original := makeExtractStore(t)
	for _, sch := range Schemes {
		sch := sch
		t.Run(sch.Name, func(t *testing.T) {
			ok, err := tryExtraction(sch, original)
			if sch.Cap.Extraction {
				if err != nil {
					t.Errorf("extraction error: %v", err)
					return
				}
				if !ok {
					t.Errorf("extracted blocks do not match original")
				}
			} else {
				if ok {
					t.Errorf("unexpected extraction success: update Cap.Extraction to true if this scheme now supports extraction")
				} else {
					t.Logf("expected: scheme does not support extraction")
				}
			}
		})
	}
}
