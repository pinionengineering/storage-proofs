package erway

import (
	"crypto/rand"
	"testing"

	"github.com/pinionengineering/storage-proofs/pdp"
)

func makeKey(t *testing.T) *pdp.PublicKey {
	t.Helper()
	pk, err := KeyGen(64) // small for test speed
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	return pk
}

func randomBlocks(t *testing.T, n, size int) [][]byte {
	t.Helper()
	blocks := make([][]byte, n)
	for i := range n {
		blocks[i] = make([]byte, size)
		if _, err := rand.Read(blocks[i]); err != nil {
			t.Fatal(err)
		}
	}
	return blocks
}

// TestBuildAndBasis checks that Build succeeds and returns a non-zero basis.
func TestBuildAndBasis(t *testing.T) {
	pk := makeKey(t)
	blocks := randomBlocks(t, 10, 32)
	sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if sl.n != 10 {
		t.Fatalf("sl.n = %d, want 10", sl.n)
	}
	allZero := true
	for _, b := range basis {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("basis is all zeros — label computation likely broken")
	}
}

// TestAtRankVerifyPath checks that every block position can be proven and verified.
func TestAtRankVerifyPath(t *testing.T) {
	pk := makeKey(t)
	blocks := randomBlocks(t, 15, 32)
	sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for pos := 1; pos <= sl.n; pos++ {
		tagBytes, steps, err := sl.atRank(pos)
		if err != nil {
			t.Fatalf("atRank(%d): %v", pos, err)
		}
		bp := BlockProof{Tag: tagBytes, Steps: steps}
		ok, err := verifyPath(basis, pos, bp)
		if err != nil {
			t.Fatalf("verifyPath(%d): %v", pos, err)
		}
		if !ok {
			t.Fatalf("verifyPath(%d): valid proof rejected", pos)
		}
	}
}

// TestProveAndVerify runs the full challenge-prove-verify cycle.
func TestProveAndVerify(t *testing.T) {
	pk := makeKey(t)
	blocks := randomBlocks(t, 20, 32)
	sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	fetch := func(i int) ([]byte, error) { return blocks[i-1], nil }

	for round := range 5 {
		chal, err := MakeChallenge(sl.n, 4)
		if err != nil {
			t.Fatalf("MakeChallenge(round=%d): %v", round, err)
		}
		proof, err := Prove(pdp.SuiteV1, pk, sl, chal, fetch)
		if err != nil {
			t.Fatalf("Prove(round=%d): %v", round, err)
		}
		ok, err := VerifyProof(pk, basis, chal, proof)
		if err != nil {
			t.Fatalf("VerifyProof(round=%d): %v", round, err)
		}
		if !ok {
			t.Fatalf("VerifyProof(round=%d): valid proof rejected", round)
		}
	}
}

// TestTamperedBlockFails checks that a wrong block causes VerifyProof to fail.
func TestTamperedBlockFails(t *testing.T) {
	pk := makeKey(t)
	blocks := randomBlocks(t, 20, 32)
	sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Serve garbage for every block.
	corruptFetch := func(_ int) ([]byte, error) {
		g := make([]byte, 32)
		rand.Read(g)
		return g, nil
	}

	anyFailed := false
	for range 10 {
		chal, _ := MakeChallenge(sl.n, 4)
		proof, err := Prove(pdp.SuiteV1, pk, sl, chal, corruptFetch)
		if err != nil {
			t.Fatalf("Prove with corrupt fetch: %v", err)
		}
		ok, err := VerifyProof(pk, basis, chal, proof)
		if err != nil {
			t.Fatalf("VerifyProof: %v", err)
		}
		if !ok {
			anyFailed = true
		}
	}
	if !anyFailed {
		t.Fatal("all challenges passed despite corrupted blocks — soundness failure")
	}
}

// TestModifyUpdate checks that a Modify update correctly advances the basis.
func TestModifyUpdate(t *testing.T) {
	pk := makeKey(t)
	blocks := randomBlocks(t, 10, 32)
	sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	newData := make([]byte, 32)
	rand.Read(newData)

	op := UpdateOp{Kind: Modify, Index: 5, Data: newData}
	result, err := PerformUpdate(pdp.SuiteV1, pk, sl, op)
	if err != nil {
		t.Fatalf("PerformUpdate: %v", err)
	}

	newBasis, ok, err := VerifyUpdate(pk, basis, op, result)
	if err != nil {
		t.Fatalf("VerifyUpdate: %v", err)
	}
	if !ok {
		t.Fatal("VerifyUpdate rejected a valid update")
	}

	// The new basis should match the skip list's actual root label.
	expectedBasis := Basis(sl.rootLabel())
	if !equal32(newBasis, expectedBasis) {
		t.Fatalf("new basis mismatch after Modify:\n  got:  %x\n  want: %x", newBasis, expectedBasis)
	}

	// Subsequent challenges against the updated skip list should pass.
	blocks[4] = newData
	fetch := func(i int) ([]byte, error) { return blocks[i-1], nil }
	chal, _ := MakeChallenge(sl.n, 4)
	proof, err := Prove(pdp.SuiteV1, pk, sl, chal, fetch)
	if err != nil {
		t.Fatalf("Prove after Modify: %v", err)
	}
	ok2, err := VerifyProof(pk, newBasis, chal, proof)
	if err != nil {
		t.Fatalf("VerifyProof after Modify: %v", err)
	}
	if !ok2 {
		t.Fatal("VerifyProof after Modify failed")
	}
}

// TestInsertUpdate checks that Insert works and the basis advances.
func TestInsertUpdate(t *testing.T) {
	pk := makeKey(t)
	blocks := randomBlocks(t, 10, 32)
	sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	newData := make([]byte, 32)
	rand.Read(newData)

	op := UpdateOp{Kind: Insert, Index: 5, Data: newData}
	result, err := PerformUpdate(pdp.SuiteV1, pk, sl, op)
	if err != nil {
		t.Fatalf("PerformUpdate(Insert): %v", err)
	}

	newBasis, ok, err := VerifyUpdate(pk, basis, op, result)
	if err != nil {
		t.Fatalf("VerifyUpdate(Insert): %v", err)
	}
	if !ok {
		t.Fatal("VerifyUpdate(Insert) rejected a valid update")
	}

	if sl.n != 11 {
		t.Fatalf("after Insert, sl.n = %d, want 11", sl.n)
	}

	// The new basis should match the skip list's actual root label.
	expectedBasis := Basis(sl.rootLabel())
	if !equal32(newBasis, expectedBasis) {
		t.Fatalf("new basis mismatch after Insert:\n  got:  %x\n  want: %x", newBasis, expectedBasis)
	}
}

// TestDeleteUpdate checks that Delete works for a mid-list block (uses atRank(i-1))
// and for block 1 (no predecessor proof), and that the basis advances correctly.
func TestDeleteUpdate(t *testing.T) {
	pk := makeKey(t)

	for _, idx := range []int{1, 5, 10} {
		blocks := randomBlocks(t, 10, 32)
		sl, basis, err := Build(pdp.SuiteV1, pk, blocks)
		if err != nil {
			t.Fatalf("idx=%d Build: %v", idx, err)
		}

		op := UpdateOp{Kind: Delete, Index: idx}
		result, err := PerformUpdate(pdp.SuiteV1, pk, sl, op)
		if err != nil {
			t.Fatalf("idx=%d PerformUpdate(Delete): %v", idx, err)
		}

		newBasis, ok, err := VerifyUpdate(pk, basis, op, result)
		if err != nil {
			t.Fatalf("idx=%d VerifyUpdate(Delete): %v", idx, err)
		}
		if !ok {
			t.Fatalf("idx=%d VerifyUpdate(Delete) rejected a valid update", idx)
		}

		if sl.n != 9 {
			t.Fatalf("idx=%d after Delete, sl.n = %d, want 9", idx, sl.n)
		}

		expectedBasis := Basis(sl.rootLabel())
		if !equal32(newBasis, expectedBasis) {
			t.Fatalf("idx=%d basis mismatch after Delete:\n  got:  %x\n  want: %x", idx, newBasis, expectedBasis)
		}

		// Proofs against the new basis should still work.
		fetch := func(i int) ([]byte, error) {
			remaining := make([][]byte, 0, len(blocks)-1)
			for j, b := range blocks {
				if j+1 != idx {
					remaining = append(remaining, b)
				}
			}
			return remaining[i-1], nil
		}
		chal, _ := MakeChallenge(sl.n, 3)
		proof, err := Prove(pdp.SuiteV1, pk, sl, chal, fetch)
		if err != nil {
			t.Fatalf("idx=%d Prove after Delete: %v", idx, err)
		}
		ok2, err := VerifyProof(pk, newBasis, chal, proof)
		if err != nil {
			t.Fatalf("idx=%d VerifyProof after Delete: %v", idx, err)
		}
		if !ok2 {
			t.Fatalf("idx=%d VerifyProof after Delete failed", idx)
		}
	}
}
