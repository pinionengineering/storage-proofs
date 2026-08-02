package erway

import (
	"testing"

	blockstore "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

func TestVerifyUpdateModify(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}

	for n := 1; n <= 40; n++ {
		for trial := 0; trial < 20; trial++ {
			blocks := randBlocks(n)
			sl, oldBasis, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blocks))
			if err != nil {
				t.Fatalf("n=%d: Build: %v", n, err)
			}
			heights := sl.Heights()

			pos := randIntN(n) + 1
			newBlock := randBlocks(1)[0]

			result, err := sl.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpModify, Pos: pos, Block: newBlock})
			if err != nil {
				t.Fatalf("n=%d trial=%d: PerformUpdate: %v", n, trial, err)
			}

			newBasis, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpModify, Pos: pos, Block: newBlock}, result)
			if err != nil {
				t.Fatalf("n=%d trial=%d: VerifyUpdate: %v", n, trial, err)
			}
			if !ok {
				t.Fatalf("n=%d trial=%d: VerifyUpdate rejected a valid modify", n, trial)
			}

			wantBlocks := append([][]byte{}, blocks...)
			wantBlocks[pos-1] = newBlock
			_, wantBasis, err := BuildWithHeights(suite.SuiteV1, pk, blockstore.NewMemStore(wantBlocks), heights)
			if err != nil {
				t.Fatalf("n=%d: rebuild: %v", n, err)
			}
			if !equal32(newBasis, wantBasis) {
				t.Fatalf("n=%d trial=%d pos=%d: derived basis mismatch\n got:  %x\n want: %x", n, trial, pos, newBasis, wantBasis)
			}
			if !equal32(sl.startLabel(), wantBasis) {
				t.Fatalf("n=%d trial=%d pos=%d: server basis mismatch after modify", n, trial, pos)
			}
		}
	}
}

func TestVerifyUpdateInsert(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}

	for n := 0; n <= 40; n++ {
		for trial := 0; trial < 30; trial++ {
			blocks := randBlocks(n)

			var sl *SkipList
			var oldBasis Basis
			var heights []int
			if n == 0 {
				sl = newEmptySkipList()
				oldBasis = make(Basis, 32)
				copy(oldBasis, sl.startLabel())
				heights = nil
			} else {
				sl, oldBasis, err = Build(suite.SuiteV1, pk, blockstore.NewMemStore(blocks))
				if err != nil {
					t.Fatalf("n=%d: Build: %v", n, err)
				}
				heights = sl.Heights()
			}

			pos := randIntN(n+1) + 1 // 1..n+1
			newBlock := randBlocks(1)[0]
			h := ChooseHeight(n + 1)

			result, err := sl.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpInsert, Pos: pos, Block: newBlock, Height: h})
			if err != nil {
				t.Fatalf("n=%d trial=%d pos=%d h=%d: PerformUpdate: %v", n, trial, pos, h, err)
			}

			newBasis, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpInsert, Pos: pos, Block: newBlock, Height: h}, result)
			if err != nil {
				t.Fatalf("n=%d trial=%d pos=%d h=%d: VerifyUpdate: %v", n, trial, pos, h, err)
			}
			if !ok {
				t.Fatalf("n=%d trial=%d pos=%d h=%d: VerifyUpdate rejected a valid insert", n, trial, pos, h)
			}

			newBlocks := make([][]byte, 0, n+1)
			newBlocks = append(newBlocks, blocks[:pos-1]...)
			newBlocks = append(newBlocks, newBlock)
			newBlocks = append(newBlocks, blocks[pos-1:]...)
			newHeights := make([]int, 0, n+1)
			newHeights = append(newHeights, heights[:pos-1]...)
			newHeights = append(newHeights, h)
			newHeights = append(newHeights, heights[pos-1:]...)

			_, wantBasis, err := BuildWithHeights(suite.SuiteV1, pk, blockstore.NewMemStore(newBlocks), newHeights)
			if err != nil {
				t.Fatalf("n=%d: rebuild: %v", n, err)
			}

			if !equal32(newBasis, wantBasis) {
				t.Fatalf("n=%d trial=%d pos=%d h=%d: derived basis mismatch\n got:  %x\n want: %x", n, trial, pos, h, newBasis, wantBasis)
			}
			if !equal32(sl.startLabel(), wantBasis) {
				t.Fatalf("n=%d trial=%d pos=%d h=%d: server basis mismatch after insert", n, trial, pos, h)
			}
			if got := sl.Heights(); !intsEqual(got, newHeights) {
				t.Fatalf("n=%d trial=%d pos=%d h=%d: Heights() = %v, want %v", n, trial, pos, h, got, newHeights)
			}
		}
	}
}

func TestVerifyUpdateDelete(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}

	for n := 1; n <= 40; n++ {
		for trial := 0; trial < 20; trial++ {
			blocks := randBlocks(n)
			sl, oldBasis, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blocks))
			if err != nil {
				t.Fatalf("n=%d: Build: %v", n, err)
			}
			heights := sl.Heights()

			pos := randIntN(n) + 1
			deletedHeight := heights[pos-1]

			result, err := sl.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpDelete, Pos: pos, Height: deletedHeight})
			if err != nil {
				t.Fatalf("n=%d trial=%d pos=%d: PerformUpdate: %v", n, trial, pos, err)
			}

			newBasis, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpDelete, Pos: pos, Height: deletedHeight}, result)
			if err != nil {
				t.Fatalf("n=%d trial=%d pos=%d: VerifyUpdate: %v", n, trial, pos, err)
			}
			if !ok {
				t.Fatalf("n=%d trial=%d pos=%d: VerifyUpdate rejected a valid delete", n, trial, pos)
			}

			wantBlocks := append(append([][]byte{}, blocks[:pos-1]...), blocks[pos:]...)
			wantHeights := append(append([]int{}, heights[:pos-1]...), heights[pos:]...)

			if n == 1 {
				wantBasis := newEmptySkipList().startLabel()
				if !equal32(newBasis, wantBasis) {
					t.Fatalf("n=1 trial=%d: derived basis mismatch on empty result\n got:  %x\n want: %x", trial, newBasis, wantBasis)
				}
				if !equal32(sl.startLabel(), wantBasis) {
					t.Fatalf("n=1 trial=%d: server basis mismatch on empty result", trial)
				}
			} else {
				_, wantBasis, err := BuildWithHeights(suite.SuiteV1, pk, blockstore.NewMemStore(wantBlocks), wantHeights)
				if err != nil {
					t.Fatalf("n=%d: rebuild: %v", n, err)
				}
				if !equal32(newBasis, wantBasis) {
					t.Fatalf("n=%d trial=%d pos=%d: derived basis mismatch\n got:  %x\n want: %x", n, trial, pos, newBasis, wantBasis)
				}
				if !equal32(sl.startLabel(), wantBasis) {
					t.Fatalf("n=%d trial=%d pos=%d: server basis mismatch after delete", n, trial, pos)
				}
			}
			if got := sl.Heights(); !intsEqual(got, wantHeights) {
				t.Fatalf("n=%d trial=%d pos=%d: Heights() = %v, want %v", n, trial, pos, got, wantHeights)
			}
		}
	}
}

func TestVerifyUpdateTamper(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}

	n := 8
	blocks := randBlocks(n)
	sl, oldBasis, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blocks))
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with a modify proof's sibling label.
	pos := 3
	newBlock := randBlocks(1)[0]
	result, err := sl.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpModify, Pos: pos, Block: newBlock})
	if err != nil {
		t.Fatal(err)
	}
	tamperIdx := -1
	for i, st := range result.Proof.Steps {
		if len(st.SibLabel) > 0 {
			tamperIdx = i
			break
		}
	}
	if tamperIdx >= 0 {
		tampered := *result
		tampered.Proof.Steps = append([]ProofStep{}, result.Proof.Steps...)
		tampered.Proof.Steps[tamperIdx].SibLabel = append([]byte{}, tampered.Proof.Steps[tamperIdx].SibLabel...)
		tampered.Proof.Steps[tamperIdx].SibLabel[0] ^= 0xFF
		_, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpModify, Pos: pos, Block: newBlock}, &tampered)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("VerifyUpdate accepted a tampered modify proof")
		}
	}

	// Tamper with an insert proof's TargetRightVal.
	blocks2 := randBlocks(n)
	sl2, oldBasis2, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blocks2))
	if err != nil {
		t.Fatal(err)
	}
	insBlock := randBlocks(1)[0]
	insResult, err := sl2.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpInsert, Pos: 4, Block: insBlock, Height: 2})
	if err != nil {
		t.Fatal(err)
	}
	tamperedIns := *insResult
	tamperedIns.Proof.TargetRightVal = append([]byte{}, insResult.Proof.TargetRightVal...)
	tamperedIns.Proof.TargetRightVal[0] ^= 0xFF
	_, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis2, UpdateOp{Kind: OpInsert, Pos: 4, Block: insBlock, Height: 2}, &tamperedIns)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("VerifyUpdate accepted a tampered insert proof (TargetRightVal)")
	}

	// Tamper with a tower-target modify's LeftProof: a lying LeftProof.TargetRightVal.
	for trial := 0; trial < 40; trial++ {
		heights := make([]int, n)
		for i := range heights {
			heights[i] = ChooseHeight(n)
		}
		blocks3 := randBlocks(n)
		sl3, oldBasis3, err := BuildWithHeights(suite.SuiteV1, pk, blockstore.NewMemStore(blocks3), heights)
		if err != nil {
			t.Fatal(err)
		}
		pos3 := 1 + trial%n
		modBlock := randBlocks(1)[0]
		result3, err := sl3.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpModify, Pos: pos3, Block: modBlock})
		if err != nil {
			t.Fatal(err)
		}
		if !result3.Proof.TargetIsTower || result3.LeftProof == nil {
			continue // only relevant when this position's target is a tower
		}
		tamperedMod := *result3
		lp := *result3.LeftProof
		lp.TargetRightVal = append([]byte{}, result3.LeftProof.TargetRightVal...)
		lp.TargetRightVal[0] ^= 0xFF
		tamperedMod.LeftProof = &lp
		_, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis3, UpdateOp{Kind: OpModify, Pos: pos3, Block: modBlock}, &tamperedMod)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("trial=%d pos=%d: VerifyUpdate accepted a tower-modify with a tampered LeftProof.TargetRightVal", trial, pos3)
		}
		return // found and tested one tower case; that's enough
	}
	t.Skip("no tower-target modify position turned up across trials")
}

func TestVerifyUpdateDeleteTamper(t *testing.T) {
	pk, err := pdp.MakePublicKey(64)
	if err != nil {
		t.Fatal(err)
	}

	n := 8
	blocks := randBlocks(n)
	sl, oldBasis, err := Build(suite.SuiteV1, pk, blockstore.NewMemStore(blocks))
	if err != nil {
		t.Fatal(err)
	}
	heights := sl.Heights()
	pos := 3
	deletedHeight := heights[pos-1]

	result, err := sl.PerformUpdate(suite.SuiteV1, pk, UpdateOp{Kind: OpDelete, Pos: pos, Height: deletedHeight})
	if err != nil {
		t.Fatal(err)
	}

	// A lying claimed height must not verify.
	_, ok, err := VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpDelete, Pos: pos, Height: deletedHeight + 1}, result)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("VerifyUpdate accepted a delete with a lying claimed height")
	}

	// A tampered PostProof must not verify.
	tampered := *result
	pp := *result.PostProof
	pp.TargetRightVal = append([]byte{}, result.PostProof.TargetRightVal...)
	pp.TargetRightVal[0] ^= 0xFF
	tampered.PostProof = &pp
	_, ok, err = VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpDelete, Pos: pos, Height: deletedHeight}, &tampered)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("VerifyUpdate accepted a delete with a tampered PostProof")
	}

	// A tampered pre-deletion Proof (wrong tag) must not verify.
	tamperedPre := *result
	tamperedPre.Proof.Target.Tag = append([]byte{}, result.Proof.Target.Tag...)
	tamperedPre.Proof.Target.Tag[0] ^= 0xFF
	_, ok, err = VerifyUpdate(suite.SuiteV1, pk, oldBasis, UpdateOp{Kind: OpDelete, Pos: pos, Height: deletedHeight}, &tamperedPre)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("VerifyUpdate accepted a delete with a tampered pre-deletion tag")
	}
}
