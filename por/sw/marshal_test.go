package sw

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

// --- SW-Priv (§3.2) ----------------------------------------------------------

// TestSWSecretKeyMarshalRoundTrip verifies that json.Marshal / json.Unmarshal
// preserves K, all Alpha scalars, and the Params (S, P).
// Reference: §3.2 Shacham-Waters ASIACRYPT 2008, Gen: pick K ∈ {0,1}^κ,
// α_1,...,α_S ← Z_P.
func TestSWSecretKeyMarshalRoundTrip(t *testing.T) {
	sk, err := KeyGen(smallParams())
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	data, err := json.Marshal(sk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var sk2 SecretKey
	if err := json.Unmarshal(data, &sk2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !bytes.Equal(sk.K, sk2.K) {
		t.Error("K mismatch after unmarshal")
	}
	if sk.Params.S != sk2.Params.S {
		t.Errorf("Params.S: got %d, want %d", sk2.Params.S, sk.Params.S)
	}
	if sk.Params.P.Cmp(sk2.Params.P) != 0 {
		t.Error("Params.P mismatch after unmarshal")
	}
	if len(sk.Alpha) != len(sk2.Alpha) {
		t.Fatalf("Alpha length: got %d, want %d", len(sk2.Alpha), len(sk.Alpha))
	}
	for i := range sk.Alpha {
		if sk.Alpha[i].Cmp(sk2.Alpha[i]) != 0 {
			t.Errorf("Alpha[%d] mismatch after unmarshal", i)
		}
	}
}

// TestSWSecretKeyMarshalUsable verifies that a round-tripped SecretKey produces
// the same verification outcome: tag blocks with the original key, then verify
// with the reconstructed key. Verify uses K and Alpha to recompute the MAC, so
// any field corruption surfaces here.
func TestSWSecretKeyMarshalUsable(t *testing.T) {
	params := smallParams()
	sk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	data, err := json.Marshal(sk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var sk2 SecretKey
	if err := json.Unmarshal(data, &sk2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	file := randomFile(t, 20, 32)
	store := blocks.NewMemStore(file)
	tags, err := TagBlocks(suite.SuiteV1, sk, store)
	if err != nil {
		t.Fatalf("TagBlocks: %v", err)
	}

	chal, err := MakeChallenge(store.IDs(), params, testChalSize)
	if err != nil {
		t.Fatalf("MakeChallenge: %v", err)
	}
	proof, err := Respond(params, store, tagsMap(tags), chal)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	// Verify with the *reconstructed* sk2; params come from sk2.Params.
	ok, err := Verify(suite.SuiteV1, &sk2, store.IDs(), chal, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify rejected valid proof from reconstructed SecretKey")
	}
}

// --- SW-Pub (§3.3) -----------------------------------------------------------

// TestPubSchemeMarshalRoundTrip verifies that json.Marshal / json.Unmarshal
// preserves the public parameters (Name, V, U) and the secret scalar α.
// The secret α is verified indirectly via TestPubSchemeMarshalUsable; here we
// check the public fields directly.
// Reference: §3.3 Shacham-Waters ASIACRYPT 2008, Gen: α ∈ Z_q, v = α·G₂,
// u₁,...,uₛ ∈ G₁, λ ∈ {0,1}¹²⁸.
func TestPubSchemeMarshalRoundTrip(t *testing.T) {
	ps, err := NewPubScheme(4)
	if err != nil {
		t.Fatalf("NewPubScheme: %v", err)
	}

	data, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var ps2 PubScheme
	if err := json.Unmarshal(data, &ps2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !bytes.Equal(ps.PubKey().Name, ps2.PubKey().Name) {
		t.Error("PubKey.Name mismatch after unmarshal")
	}
	if ps.PubKey().V != ps2.PubKey().V {
		t.Error("PubKey.V mismatch after unmarshal")
	}
	if len(ps.PubKey().U) != len(ps2.PubKey().U) {
		t.Fatalf("PubKey.U length: got %d, want %d", len(ps2.PubKey().U), len(ps.PubKey().U))
	}
	for i := range ps.PubKey().U {
		if ps.PubKey().U[i] != ps2.PubKey().U[i] {
			t.Errorf("PubKey.U[%d] mismatch after unmarshal", i)
		}
	}
}

// TestPubSchemeMarshalUsable verifies that a round-tripped PubScheme can tag
// new blocks and have those tags verified with the reconstructed public key.
// This exercises the secret α: if α is corrupted, σ_i = α·(...) is wrong and
// the pairing check fails.
func TestPubSchemeMarshalUsable(t *testing.T) {
	ps, err := NewPubScheme(4)
	if err != nil {
		t.Fatalf("NewPubScheme: %v", err)
	}

	data, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var ps2 PubScheme
	if err := json.Unmarshal(data, &ps2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Tag with the *reconstructed* ps2; verify with ps2.PubKey().
	file := randomFile(t, 10, 32)
	store := blocks.NewMemStore(file)
	tags, err := ps2.TagBlocks(store)
	if err != nil {
		t.Fatalf("TagBlocks: %v", err)
	}

	chal, err := ps2.MakeChallenge(store.IDs(), testChalSize)
	if err != nil {
		t.Fatalf("MakeChallenge: %v", err)
	}
	proof, err := ps2.RespondFetch(rawTagsMap(tags), chal, store)
	if err != nil {
		t.Fatalf("RespondFetch: %v", err)
	}

	ok, err := ps2.Verify(chal, proof, store.IDs())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify rejected valid proof from reconstructed PubScheme")
	}
}
