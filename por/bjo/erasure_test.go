package bjo

// End-to-end test for the erasure.go helpers: a caller supplies their own
// outer erasure coding (ErasureEncodeStore, standing in for whatever scheme
// a real caller brings) instead of por/bjo's own SA-ECC, uploads the
// already-redundant representation, loses some blocks at the simulated
// server, and recovers the original file via ExtractPhaseIStore +
// ErasureDecodeStore -- the exact flow erasure.go's package doc describes.

import (
	"bytes"
	"math/big"
	"testing"

	blockstore "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

// storeBlocks reads every block out of a BlockStore in position order.
func storeBlocks(t *testing.T, store blockstore.BlockStore) [][]byte {
	t.Helper()
	n := store.Len()
	out := make([][]byte, n)
	for i := range n {
		b, err := blockstore.BlockAt(store, i)
		if err != nil {
			t.Fatalf("BlockAt(%d): %v", i, err)
		}
		out[i] = b
	}
	return out
}

func TestExternalErasureCoding_EndToEnd(t *testing.T) {
	const (
		outerK = 4 // matches defaultParams()/phaseIParams()'s convention elsewhere in this package
		outerN = 6 // 2 parity blocks per stripe -> tolerates up to 2 losses per stripe
	)
	original := randomBlocks(t, 8, 3) // 3-byte blocks, 2 stripes of 4

	// 1. Caller applies their own erasure coding before this ever reaches
	// por/bjo's Encode.
	rawStore := blockstore.NewMemStore(original)
	encodedStore, err := ErasureEncodeStore(rawStore, outerK, outerN)
	if err != nil {
		t.Fatalf("ErasureEncodeStore: %v", err)
	}
	if encodedStore.Len() != 12 { // 2 stripes * 6
		t.Fatalf("encodedStore.Len() = %d, want 12", encodedStore.Len())
	}

	// 2. Encode with por/bjo's own outer layer set to pass-through
	// (OuterN=OuterK=encodedStore.Len()): the redundancy already present in
	// encodedStore is all there is, and all there needs to be.
	params := &Params{
		V:      3,
		W:      10,
		Q:      5,
		P:      big.NewInt(2147483647),
		OuterN: encodedStore.Len(),
		OuterK: encodedStore.Len(),
		Alpha:  10,
		Delta:  0.25,
	}
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	ef, err := Encode(suite.SuiteV1, mk, encodedStore)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// 3. Simulate the server losing one block per stripe (positions 0 and
	// 6), each within that stripe's outerN-outerK=2-loss budget.
	lossy := make([][]byte, len(ef.Blocks))
	copy(lossy, ef.Blocks)
	lossy[0] = nil
	lossy[6] = nil
	lossyEF := &EncodedFile{
		Blocks:     lossy,
		NumMessage: ef.NumMessage,
		Sentinels:  ef.Sentinels,
		FileMAC:    ef.FileMAC,
		Params:     ef.Params,
	}

	// 4. Recover: Phase I (now fixed) reports the two lost blocks as
	// erasures rather than confidently-wrong zeros; ErasureDecodeStore then
	// fills them in using the external RS parity from step 1.
	phaseIStore, err := ExtractPhaseIStore(suite.SuiteV1, mk, lossyEF)
	if err != nil {
		t.Fatalf("ExtractPhaseIStore: %v", err)
	}
	fileStore, err := ErasureDecodeStore(phaseIStore, len(original), outerK, outerN)
	if err != nil {
		t.Fatalf("ErasureDecodeStore: %v", err)
	}

	recovered := storeBlocks(t, fileStore)
	if len(recovered) != len(original) {
		t.Fatalf("recovered %d blocks, want %d", len(recovered), len(original))
	}
	for i := range original {
		if !bytes.Equal(recovered[i], original[i]) {
			t.Fatalf("block %d: recovered %x, want %x", i, recovered[i], original[i])
		}
	}

	// 5. A real caller (not just this test, which already has `original`
	// to compare against) verifies success via the file MAC. VerifyFileMAC
	// needs the file shaped exactly like whatever was fed to Encode -- here
	// that's the full 12-block erasure-coded representation, not the true
	// 8-block original, so re-derive it (deterministic, no keys involved in
	// this plain RS layer, so this reproduces encodedStore's original
	// content exactly).
	reconstructed, err := ErasureEncodeStore(blockstore.NewMemStore(recovered), outerK, outerN)
	if err != nil {
		t.Fatalf("ErasureEncodeStore (re-derive for MAC check): %v", err)
	}
	ok, err := VerifyFileMAC(suite.SuiteV1, mk, ef, storeBlocks(t, reconstructed))
	if err != nil {
		t.Fatalf("VerifyFileMAC: %v", err)
	}
	if !ok {
		t.Fatal("VerifyFileMAC: reconstructed file does not match the stored MAC")
	}
}

// TestExternalErasureCoding_TooManyLossesFails confirms losing more blocks
// than a stripe's redundancy budget correctly fails (not silently returns
// wrong data), for both ExtractPhaseIStore's own recovery and
// ErasureDecodeStore's downstream reconstruction.
func TestExternalErasureCoding_TooManyLossesFails(t *testing.T) {
	const outerK, outerN = 4, 6 // budget: 2 losses per stripe
	original := randomBlocks(t, 4, 3)

	rawStore := blockstore.NewMemStore(original)
	encodedStore, err := ErasureEncodeStore(rawStore, outerK, outerN)
	if err != nil {
		t.Fatalf("ErasureEncodeStore: %v", err)
	}

	params := &Params{
		V: 3, W: 10, Q: 5, P: big.NewInt(2147483647),
		OuterN: encodedStore.Len(), OuterK: encodedStore.Len(),
		Alpha: 10, Delta: 0.25,
	}
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	ef, err := Encode(suite.SuiteV1, mk, encodedStore)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Lose 3 of the 6 blocks in the single stripe -- one more than the
	// outerN-outerK=2 budget.
	lossy := make([][]byte, len(ef.Blocks))
	copy(lossy, ef.Blocks)
	lossy[0], lossy[1], lossy[2] = nil, nil, nil
	lossyEF := &EncodedFile{Blocks: lossy, NumMessage: ef.NumMessage, Sentinels: ef.Sentinels, FileMAC: ef.FileMAC, Params: ef.Params}

	phaseIStore, err := ExtractPhaseIStore(suite.SuiteV1, mk, lossyEF)
	if err != nil {
		t.Fatalf("ExtractPhaseIStore: %v", err)
	}
	if _, err := ErasureDecodeStore(phaseIStore, len(original), outerK, outerN); err == nil {
		t.Fatal("ErasureDecodeStore succeeded despite exceeding the erasure budget -- should have failed loudly")
	}
}
