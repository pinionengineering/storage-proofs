package capability

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
)

// marshalKeySizes is the set of RSA key bit lengths exercised by
// TestMarshalTaggerRoundTrip. For schemes that ignore keyBits (SW-Priv,
// SW-Pub, BJO), the loop still runs but every iteration generates its own
// independent key material since NewTagger never caches.
var marshalKeySizes = []int{128, 256, 512}

const marshalChalSize = 5

// TestMarshalTaggerRoundTrip exercises MarshalTagger / UnmarshalTagger for
// every scheme × key size combination.
//
// Each sub-test:
//  1. Tags an initial store with a freshly generated key.
//  2. Marshals the tagger, unmarshals into a new tagger instance.
//  3. Re-marshals the new instance and asserts byte-for-byte equality with the
//     original blob (idempotency — catches truncation or field reordering bugs).
//  4. Tags a SECOND, distinct store using the reconstructed tagger (the multi-root
//     scenario: same key, different blocks). This is the primary use-case test.
//  5. Runs a complete challenge → prove → verify cycle on the second store to
//     confirm all key material survived serialization intact.
func TestMarshalTaggerRoundTrip(t *testing.T) {
	for _, sch := range Schemes {
		sch := sch
		if sch.MarshalTagger == nil || sch.UnmarshalTagger == nil {
			continue
		}
		for _, keyBits := range marshalKeySizes {
			keyBits := keyBits
			name := fmt.Sprintf("%s/%dbits", sch.Name, keyBits)
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				// ── 1. Tag with original tagger ─────────────────────────────
				store1 := makeExtractStore(t)
				tagger1, err := sch.NewTagger(keyBits, marshalChalSize, testBlockSize, extractSectorsPerBlock)
				if err != nil {
					t.Fatalf("NewTagger: %v", err)
				}
				if _, err := tagger1.TagBlocks(store1); err != nil {
					t.Fatalf("TagBlocks (original): %v", err)
				}

				// ── 2. Serialize ─────────────────────────────────────────────
				blob, err := sch.MarshalTagger(tagger1)
				if err != nil {
					t.Fatalf("MarshalTagger: %v", err)
				}

				// ── 3. Reconstruct ───────────────────────────────────────────
				tagger2, err := sch.UnmarshalTagger(blob)
				if err != nil {
					t.Fatalf("UnmarshalTagger: %v", err)
				}

				// ── 4. Idempotency: re-marshal and compare ───────────────────
				blob2, err := sch.MarshalTagger(tagger2)
				if err != nil {
					t.Fatalf("MarshalTagger (round-tripped): %v", err)
				}
				if !bytes.Equal(blob, blob2) {
					t.Errorf("MarshalTagger not idempotent after round-trip\n  first:  %s\n  second: %s", blob, blob2)
				}

				// ── 5. Tag new blocks with the reconstructed tagger ──────────
				store2 := makeExtractStore(t)
				if _, err := tagger2.TagBlocks(store2); err != nil {
					t.Fatalf("TagBlocks (reconstructed): %v", err)
				}

				// ── 6. Full challenge / prove / verify on the second store ────
				clientSetup, err := tagger2.ClientSetup()
				if err != nil {
					t.Fatalf("ClientSetup: %v", err)
				}
				proverSetup, err := tagger2.ProverSetup()
				if err != nil {
					t.Fatalf("ProverSetup: %v", err)
				}
				encoded := tagger2.EncodedBlocks()

				challenger, err := sch.ChalFactory.NewChallenger(clientSetup, marshalChalSize)
				if err != nil {
					t.Fatalf("NewChallenger: %v", err)
				}
				prover, err := sch.ProvFactory.NewProver(proverSetup, encoded)
				if err != nil {
					t.Fatalf("NewProver: %v", err)
				}

				chal, validator, err := challenger.Challenge(encoded.Len(), blocks.IDAtFunc(encoded))
				if err != nil {
					t.Fatalf("Challenge: %v", err)
				}
				proof, err := prover.Prove(chal, encoded)
				if err != nil {
					t.Fatalf("Prove: %v", err)
				}
				ok, err := validator.Verify(chal, proof)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if !ok {
					t.Fatal("proof verification failed after UnmarshalTagger")
				}
			})
		}
	}
}
