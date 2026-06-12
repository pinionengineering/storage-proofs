package pdp

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestPublicKeyMarshalRoundTrip verifies that json.Marshal / json.Unmarshal
// preserves N and G exactly across a range of key sizes. Varying the size
// exercises the big.Int.Bytes() / SetBytes() path at different byte lengths,
// including values that may have leading zero bytes when serialized.
func TestPublicKeyMarshalRoundTrip(t *testing.T) {
	for _, bits := range []int{64, 128, 256, 512} {
		bits := bits
		t.Run(fmt.Sprintf("%dbits", bits), func(t *testing.T) {
			t.Parallel()
			pk, err := MakePublicKey(bits)
			if err != nil {
				t.Fatalf("MakePublicKey(%d): %v", bits, err)
			}

			data, err := json.Marshal(pk)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}

			var pk2 PublicKey
			if err := json.Unmarshal(data, &pk2); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}

			if pk.N.Cmp(pk2.N) != 0 {
				t.Errorf("N mismatch after unmarshal")
			}
			if pk.G.Cmp(pk2.G) != 0 {
				t.Errorf("G mismatch after unmarshal")
			}
		})
	}
}
