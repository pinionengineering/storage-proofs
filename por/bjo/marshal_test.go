package bjo

import (
	"bytes"
	"encoding/json"
	"testing"

	blockstore "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

// TestMasterKeyMarshalRoundTrip verifies that json.Marshal / json.Unmarshal
// preserves all seven derived sub-keys and the Params (including P and GSeed).
// Reference: §4.2.1 Bowers, Juels, Oprea — KeyGen derives KChal, KInd,
// KMACFile, KEnc, KPerm, KECCPerm, KECCEnc from a master secret.
func TestMasterKeyMarshalRoundTrip(t *testing.T) {
	params := &Params{
		V: 5, W: 20, Q: 10,
		P:      smallP,
		OuterN: 8, OuterK: 4,
	}
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	data, err := json.Marshal(mk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var mk2 MasterKey
	if err := json.Unmarshal(data, &mk2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, tc := range []struct {
		name      string
		orig, got []byte
	}{
		{"KChal", mk.KChal, mk2.KChal},
		{"KInd", mk.KInd, mk2.KInd},
		{"KMACFile", mk.KMACFile, mk2.KMACFile},
		{"KEnc", mk.KEnc, mk2.KEnc},
		{"KPerm", mk.KPerm, mk2.KPerm},
		{"KECCPerm", mk.KECCPerm, mk2.KECCPerm},
		{"KECCEnc", mk.KECCEnc, mk2.KECCEnc},
		{"Params.GSeed", mk.Params.GSeed, mk2.Params.GSeed},
	} {
		if !bytes.Equal(tc.orig, tc.got) {
			t.Errorf("%s mismatch after unmarshal", tc.name)
		}
	}
	if mk.Params.P.Cmp(mk2.Params.P) != 0 {
		t.Error("Params.P mismatch after unmarshal")
	}
	if mk.Params.V != mk2.Params.V || mk.Params.W != mk2.Params.W ||
		mk.Params.Q != mk2.Params.Q || mk.Params.OuterN != mk2.Params.OuterN ||
		mk.Params.OuterK != mk2.Params.OuterK {
		t.Error("Params integer fields mismatch after unmarshal")
	}
}

// TestMasterKeyMarshalUsable verifies that a round-tripped MasterKey can
// participate in the full POR protocol: encode with the original key, then
// challenge and verify using the *reconstructed* key. Verify decrypts the
// sentinel using mk2.KEnc, so any key corruption surfaces here.
func TestMasterKeyMarshalUsable(t *testing.T) {
	params := &Params{
		V: 5, W: 20, Q: 10,
		P:      smallP,
		OuterN: 8, OuterK: 4,
	}
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	data, err := json.Marshal(mk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var mk2 MasterKey
	if err := json.Unmarshal(data, &mk2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Encode using the original mk (simulates what was stored at setup time).
	file := simpleFile(t, 50)
	ef, err := Encode(suite.SuiteV1, mk, blockstore.NewMemStore(file))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Challenge and verify using the *reconstructed* mk2.
	for j := 1; j <= mk2.Params.Q; j++ {
		chal, err := MakeChallenge(&mk2, j)
		if err != nil {
			t.Fatalf("MakeChallenge(j=%d): %v", j, err)
		}
		resp, err := Respond(suite.SuiteV1, ef, chal)
		if err != nil {
			t.Fatalf("Respond(j=%d): %v", j, err)
		}
		ok, err := Verify(&mk2, chal, resp)
		if err != nil {
			t.Fatalf("Verify(j=%d): %v", j, err)
		}
		if !ok {
			t.Fatalf("Verify(j=%d): rejected valid proof from reconstructed MasterKey", j)
		}
	}
}
