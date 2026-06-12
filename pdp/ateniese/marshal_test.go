package ateniese

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	blockstore "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

// TestAteniesesSecretKeyMarshalRoundTrip verifies that json.Marshal /
// json.Unmarshal preserves all four fields (E, D, V, Phi) across a range of
// key sizes. Reference: §4.3 Ateniese et al., CCS 2007 KeyGen: e, d, v, phi.
func TestAteniesesSecretKeyMarshalRoundTrip(t *testing.T) {
	for _, bits := range []int{64, 128, 256, 512} {
		bits := bits
		t.Run(fmt.Sprintf("%dbits", bits), func(t *testing.T) {
			t.Parallel()
			_, sk, err := KeyGen(bits)
			if err != nil {
				t.Fatalf("KeyGen(%d): %v", bits, err)
			}

			data, err := json.Marshal(sk)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}

			var sk2 SecretKey
			if err := json.Unmarshal(data, &sk2); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}

			if sk.E.Cmp(sk2.E) != 0 {
				t.Error("E mismatch after unmarshal")
			}
			if sk.D.Cmp(sk2.D) != 0 {
				t.Error("D mismatch after unmarshal")
			}
			if !bytes.Equal(sk.V, sk2.V) {
				t.Error("V mismatch after unmarshal")
			}
			if sk.Phi.Cmp(sk2.Phi) != 0 {
				t.Error("Phi mismatch after unmarshal")
			}
		})
	}
}

// TestAteniesesSecretKeyMarshalUsable verifies that a round-tripped SecretKey
// (and its paired PublicKey) can be used for a full S-PDP proof: tag → challenge
// → GenProof → CheckProof all pass with the reconstructed keys, not the originals.
func TestAteniesesSecretKeyMarshalUsable(t *testing.T) {
	for _, bits := range []int{64, 128, 256} {
		bits := bits
		t.Run(fmt.Sprintf("%dbits", bits), func(t *testing.T) {
			t.Parallel()
			pk, sk, err := KeyGen(bits)
			if err != nil {
				t.Fatalf("KeyGen(%d): %v", bits, err)
			}

			// Round-trip both keys.
			skData, err := json.Marshal(sk)
			if err != nil {
				t.Fatalf("json.Marshal sk: %v", err)
			}
			var sk2 SecretKey
			if err := json.Unmarshal(skData, &sk2); err != nil {
				t.Fatalf("json.Unmarshal sk: %v", err)
			}

			pkData, err := json.Marshal(pk)
			if err != nil {
				t.Fatalf("json.Marshal pk: %v", err)
			}
			var pk2 pdp.PublicKey
			if err := json.Unmarshal(pkData, &pk2); err != nil {
				t.Fatalf("json.Unmarshal pk: %v", err)
			}

			// Tag blocks using the *original* keys (simulates what was stored at setup time).
			blocks := simpleFile(t, 10)
			tags := make([]*Tag, len(blocks))
			for i, block := range blocks {
				w := append(append([]byte(nil), sk.V...), byte(i))
				tags[i], err = TagBlock(suite.SuiteV1, pk, sk, block, w)
				if err != nil {
					t.Fatalf("TagBlock(%d): %v", i, err)
				}
			}

			// Build a challenge.
			s, err := rand.Int(rand.Reader, pk.N)
			if err != nil {
				t.Fatalf("rand.Int: %v", err)
			}
			k1, k2 := make([]byte, 16), make([]byte, 16)
			rand.Read(k1)
			rand.Read(k2)
			chal := &Challenge{
				SuiteID: suite.SuiteV1.ID(),
				C:       4,
				K1:      k1,
				K2:      k2,
				Gs:      new(big.Int).Exp(pk.G, s, pk.N),
			}

			// Server generates proof.
			proof, err := GenProof(suite.SuiteV1, &pk2, blockstore.NewMemStore(blocks), chal, tags)
			if err != nil {
				t.Fatalf("GenProof: %v", err)
			}

			// Client verifies using the *reconstructed* sk2 and pk2.
			ok, err := CheckProof(suite.SuiteV1, &pk2, &sk2, s, tags, chal, proof)
			if err != nil {
				t.Fatalf("CheckProof: %v", err)
			}
			if !ok {
				t.Fatal("CheckProof rejected valid proof from reconstructed keys")
			}
		})
	}
}
