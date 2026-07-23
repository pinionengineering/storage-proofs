package capability

import (
	"bytes"
	"testing"
)

// TestNewTaggerGeneratesFreshKeyMaterial guards against the class of bug where
// NewTagger cached and reused key material across calls with identical
// parameters (previously true for all five schemes here, since the cache key
// was only the server-wide-constant call parameters, which never vary in
// production). Two invocations with identical arguments must produce two
// distinct private keys, since each challenge key must be independent — never
// shared across accounts or requests.
func TestNewTaggerGeneratesFreshKeyMaterial(t *testing.T) {
	for _, sch := range Schemes {
		sch := sch
		t.Run(sch.Name, func(t *testing.T) {
			if sch.MarshalTagger == nil {
				t.Skip("scheme does not support key serialization")
			}

			tagger1, err := sch.NewTagger(extractKeyBits, extractChalSize, testBlockSize, extractSectorsPerBlock)
			if err != nil {
				t.Fatalf("NewTagger (first): %v", err)
			}
			tagger2, err := sch.NewTagger(extractKeyBits, extractChalSize, testBlockSize, extractSectorsPerBlock)
			if err != nil {
				t.Fatalf("NewTagger (second): %v", err)
			}

			blob1, err := sch.MarshalTagger(tagger1)
			if err != nil {
				t.Fatalf("MarshalTagger (first): %v", err)
			}
			blob2, err := sch.MarshalTagger(tagger2)
			if err != nil {
				t.Fatalf("MarshalTagger (second): %v", err)
			}

			if bytes.Equal(blob1, blob2) {
				t.Fatalf("two NewTagger calls with identical parameters produced identical key material: %s", blob1)
			}
		})
	}
}
