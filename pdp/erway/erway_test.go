package erway

import (
	"crypto/rand"
	"fmt"
	"testing"

	blockstore "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

func randBlocks(n int) [][]byte {
	blks := make([][]byte, n)
	for i := range blks {
		blks[i] = make([]byte, 32)
		rand.Read(blks[i])
	}
	return blks
}

func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	v := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if v < 0 {
		v = -v
	}
	return v % n
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func checkAllPositions(t *testing.T, sl *SkipList, basis Basis, label string) {
	t.Helper()
	for pos := 1; pos <= sl.n; pos++ {
		bp, err := sl.atRank(pos)
		if err != nil {
			t.Fatalf("%s: atRank(%d): %v", label, pos, err)
		}
		ok, err := verifyPath(basis, pos, bp)
		if err != nil {
			t.Fatalf("%s: verifyPath(%d): %v", label, pos, err)
		}
		if !ok {
			t.Fatalf("%s: verifyPath(%d) rejected valid proof", label, pos)
		}
	}
}

func TestBuildProveVerify(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2, 3, 5, 10, 30, 60, 120} {
		for trial := 0; trial < 40; trial++ {
			blks := randBlocks(n)
			sl, basis, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blks))
			if err != nil {
				t.Fatalf("n=%d Build: %v", n, err)
			}
			checkAllPositions(t, sl, basis, fmt.Sprintf("n=%d trial=%d", n, trial))

			c := 6
			if c > n {
				c = n
			}
			chal, err := MakeChallenge(n, c)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := Prove(suite.SuiteV1, pk, sl, chal, blockstore.NewMemStore(blks))
			if err != nil {
				t.Fatalf("n=%d Prove: %v", n, err)
			}
			ok, err := Verify(pk, basis, chal, proof)
			if err != nil {
				t.Fatalf("n=%d Verify: %v", n, err)
			}
			if !ok {
				t.Fatalf("n=%d trial=%d Verify rejected valid proof", n, trial)
			}
		}
	}
}

// TestTamperedBlockRejected checks that Verify fails when the server proves
// against block data that doesn't match the tags recorded in the skip list
// (§4.2's blockless check, g^M = ∏ T(blockᵢⱼ)^aⱼ, must not accept content
// the tags never committed to).
func TestTamperedBlockRejected(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}
	n := 20
	blks := randBlocks(n)
	sl, basis, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blks))
	if err != nil {
		t.Fatal(err)
	}

	anyRejected := false
	for trial := 0; trial < 10; trial++ {
		corrupt := randBlocks(n)
		chal, err := MakeChallenge(n, 4)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := Prove(suite.SuiteV1, pk, sl, chal, blockstore.NewMemStore(corrupt))
		if err != nil {
			t.Fatalf("Prove with corrupted blocks: %v", err)
		}
		ok, err := Verify(pk, basis, chal, proof)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			anyRejected = true
		}
	}
	if !anyRejected {
		t.Fatal("every challenge against corrupted block data still verified")
	}
}

func TestModifyAtMatchesRebuild(t *testing.T) {
	pk, _ := pdp.MakePublicKey(64)
	for _, n := range []int{1, 2, 3, 5, 10, 30} {
		for trial := 0; trial < 20; trial++ {
			blks := randBlocks(n)
			sl, _, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blks))
			if err != nil {
				t.Fatal(err)
			}
			heights := sl.Heights()
			pos := 1 + trial%n
			newData := make([]byte, 32)
			rand.Read(newData)
			if err := sl.modifyAt(suite.SuiteV1, pk, pos, newData); err != nil {
				t.Fatalf("n=%d pos=%d: modifyAt: %v", n, pos, err)
			}
			blks[pos-1] = newData
			_, wantBasis, err := BuildWithHeights(suite.SuiteV1, pk, blockstore.NewMemStore(blks), heights)
			if err != nil {
				t.Fatal(err)
			}
			gotBasis := Basis(sl.startLabel())
			if !equal32(gotBasis, wantBasis) {
				t.Fatalf("n=%d trial=%d pos=%d: basis mismatch after modify\n got:  %x\n want: %x", n, trial, pos, gotBasis, wantBasis)
			}
			checkAllPositions(t, sl, gotBasis, fmt.Sprintf("n=%d modify pos=%d", n, pos))
		}
	}
}

func TestDeleteAtMatchesRebuild(t *testing.T) {
	pk, _ := pdp.MakePublicKey(64)
	for _, n := range []int{2, 3, 5, 10, 30} {
		for trial := 0; trial < 20; trial++ {
			blks := randBlocks(n)
			sl, _, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blks))
			if err != nil {
				t.Fatal(err)
			}
			heights := sl.Heights()
			pos := 1 + trial%n
			if err := sl.deleteAt(pos); err != nil {
				t.Fatalf("n=%d pos=%d: deleteAt: %v", n, pos, err)
			}
			remainingBlks := append(append([][]byte{}, blks[:pos-1]...), blks[pos:]...)
			remainingHeights := append(append([]int{}, heights[:pos-1]...), heights[pos:]...)
			_, wantBasis, err := BuildWithHeights(suite.SuiteV1, pk, blockstore.NewMemStore(remainingBlks), remainingHeights)
			if err != nil {
				t.Fatal(err)
			}
			gotBasis := Basis(sl.startLabel())
			if !equal32(gotBasis, wantBasis) {
				t.Fatalf("n=%d trial=%d pos=%d: basis mismatch after delete\n got:  %x\n want: %x", n, trial, pos, gotBasis, wantBasis)
			}
			checkAllPositions(t, sl, gotBasis, fmt.Sprintf("n=%d delete pos=%d", n, pos))
		}
	}
}

// TestMixedSequence runs a long randomized sequence of low-level
// insert/modify/delete mutations and checks, after every step, that every
// position still proves correctly and holds the expected tag — a stress
// test for the tower/plateau label formula (f) across arbitrary structural
// change, not just single edits from a fresh build.
func TestMixedSequence(t *testing.T) {
	pk, _ := pdp.MakePublicKey(64)
	blks := randBlocks(3)
	sl, _, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blks))
	if err != nil {
		t.Fatal(err)
	}
	expectedTags := make([][]byte, 3)
	for i, b := range blks {
		expectedTags[i] = BlockTag(suite.SuiteV1, pk, b).Bytes()
	}

	ops := []string{}
	for step := 0; step < 1000; step++ {
		n := sl.n
		choice := step % 5
		switch {
		case choice < 2 || n <= 1:
			pos := randIntN(n + 1)
			h := ChooseHeight(n)
			data := make([]byte, 32)
			rand.Read(data)
			ops = append(ops, fmt.Sprintf("insert@%d h=%d", pos, h))
			if err := sl.doInsert(suite.SuiteV1, pk, pos+1, data, h); err != nil {
				t.Fatalf("step %d (%v): doInsert: %v", step, ops, err)
			}
			tag := BlockTag(suite.SuiteV1, pk, data).Bytes()
			expectedTags = append(expectedTags[:pos], append([][]byte{tag}, expectedTags[pos:]...)...)
		case choice == 2:
			pos := 1 + randIntN(n)
			data := make([]byte, 32)
			rand.Read(data)
			ops = append(ops, fmt.Sprintf("modify@%d", pos))
			if err := sl.modifyAt(suite.SuiteV1, pk, pos, data); err != nil {
				t.Fatalf("step %d (%v): modifyAt: %v", step, ops, err)
			}
			expectedTags[pos-1] = BlockTag(suite.SuiteV1, pk, data).Bytes()
		default:
			pos := 1 + randIntN(n)
			ops = append(ops, fmt.Sprintf("delete@%d", pos))
			if err := sl.deleteAt(pos); err != nil {
				t.Fatalf("step %d (%v): deleteAt: %v", step, ops, err)
			}
			expectedTags = append(expectedTags[:pos-1], expectedTags[pos:]...)
		}

		if sl.n != len(expectedTags) {
			t.Fatalf("step %d (%v): sl.n=%d but expected %d blocks", step, ops, sl.n, len(expectedTags))
		}

		basis := Basis(sl.startLabel())
		for pos := 1; pos <= sl.n; pos++ {
			bp, err := sl.atRank(pos)
			if err != nil {
				t.Fatalf("step %d (%v): atRank(%d): %v", step, ops, pos, err)
			}
			ok, err := verifyPath(basis, pos, bp)
			if err != nil {
				t.Fatalf("step %d (%v): verifyPath(%d): %v", step, ops, pos, err)
			}
			if !ok {
				t.Fatalf("step %d (%v): verifyPath(%d) rejected valid proof, n=%d", step, ops, pos, sl.n)
			}
			if bp.Target.Tag == nil || string(bp.Target.Tag) != string(expectedTags[pos-1]) {
				t.Fatalf("step %d (%v): position %d has wrong content (data reordered/lost)", step, ops, pos)
			}
		}
	}
}
