package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"syscall"

	blockspkg "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/capability"
	"github.com/pinionengineering/storage-proofs/line"
)

// schemeSpec wraps capability.SchemeSpec with display metadata for the study.
type schemeSpec struct {
	capability.SchemeSpec
	color string
}

var schemes = []schemeSpec{
	{SchemeSpec: capability.Schemes[0], color: "#3b82f6"}, // Ateniese
	{SchemeSpec: capability.Schemes[1], color: "#ef4444"}, // Erway
	{SchemeSpec: capability.Schemes[2], color: "#f59e0b"}, // SW-Priv
	{SchemeSpec: capability.Schemes[3], color: "#10b981"}, // BJO
	{SchemeSpec: capability.Schemes[4], color: "#8b5cf6"}, // SW-Pub
}

// Params describes one experimental condition.
type Params struct {
	KeyBits  int
	NBlocks  int
	ChalSize int
}

// Metrics holds every quantity measurable from one experiment run.
type Metrics struct {
	SetupTime      int64 // µs, averaged over benchReps
	ProveTime      int64 // µs
	VerifyTime     int64 // µs
	ChalLen        int   // bytes
	ProofLen       int   // bytes
	ClientSetupLen int   // bytes
	ServerSetupLen int   // bytes
}

// run executes one complete protocol round for the given scheme and parameters
// using the line interfaces uniformly. This is the innermost experiment loop.
func run(sch schemeSpec, store blockspkg.BlockStore, p Params) (Metrics, error) {
	tagger, err := sch.NewTagger(p.KeyBits, p.ChalSize)
	if err != nil {
		return Metrics{}, fmt.Errorf("%s newTagger: %w", sch.Name, err)
	}

	// Time TagBlocks (server setup).
	setupTime, err := timeOp(benchReps, func() error { _, e := tagger.TagBlocks(store); return e })
	if err != nil {
		return Metrics{}, fmt.Errorf("%s tag: %w", sch.Name, err)
	}
	if _, err = tagger.TagBlocks(store); err != nil { // final call for consistent state
		return Metrics{}, fmt.Errorf("%s tag final: %w", sch.Name, err)
	}

	encoded := tagger.EncodedBlocks()
	clientSetup, err := tagger.ClientSetup()
	if err != nil {
		return Metrics{}, err
	}
	proverSetup, err := tagger.ProverSetup()
	if err != nil {
		return Metrics{}, err
	}

	challenger, err := sch.ChalFactory.NewChallenger(clientSetup, p.ChalSize)
	if err != nil {
		return Metrics{}, err
	}
	prover, err := sch.ProvFactory.NewProver(proverSetup, encoded)
	if err != nil {
		return Metrics{}, err
	}

	chal, validator, err := challenger.Challenge(encoded.IDs())
	if err != nil {
		return Metrics{}, err
	}

	chalLen := len(chal)
	if cs, ok := challenger.(line.ChalSizer); ok {
		chalLen = cs.ChalBytes(chal)
	}

	var proof line.Proof
	proveTime, err := timeOp(benchReps, func() error {
		var e error
		proof, e = prover.Prove(chal, encoded)
		return e
	})
	if err != nil {
		return Metrics{}, err
	}

	proofLen := len(proof)
	if ps, ok := prover.(line.ProofSizer); ok {
		proofLen = ps.ProofBytes(proof)
	}

	verifyTime, err := timeOp(benchReps, func() error {
		_, e := validator.Verify(chal, proof)
		return e
	})
	if err != nil {
		return Metrics{}, err
	}

	return Metrics{
		SetupTime:      setupTime,
		ProveTime:      proveTime,
		VerifyTime:     verifyTime,
		ChalLen:        chalLen,
		ProofLen:       proofLen,
		ClientSetupLen: len(clientSetup),
		ServerSetupLen: len(proverSetup),
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func cpuMicros(ru syscall.Rusage) int64 {
	return ru.Utime.Sec*1e6 + int64(ru.Utime.Usec) +
		ru.Stime.Sec*1e6 + int64(ru.Stime.Usec)
}

// timeOp measures CPU time (not wall clock) by pinning the goroutine to its
// OS thread and reading RUSAGE_THREAD before and after. This makes measurements
// valid even when multiple goroutines run concurrently.
func timeOp(reps int, f func() error) (int64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_THREAD, &before) //nolint:errcheck
	for range reps {
		if err := f(); err != nil {
			return 0, err
		}
	}
	syscall.Getrusage(syscall.RUSAGE_THREAD, &after) //nolint:errcheck
	return (cpuMicros(after) - cpuMicros(before)) / int64(reps), nil
}

func randomBlocks(n int) [][]byte        { return randomBlocksOfSize(n, fixedBlockSz) }
func randomBlocksOfSize(n, sz int) [][]byte {
	blks := make([][]byte, n)
	for i := range n {
		blks[i] = make([]byte, sz)
		rand.Read(blks[i]) //nolint:errcheck
	}
	return blks
}

func corruptBlocks(original [][]byte, indices []int) [][]byte {
	out := make([][]byte, len(original))
	copy(out, original)
	for _, i := range indices {
		b := make([]byte, len(original[i]))
		copy(b, original[i])
		b[0] ^= 0xFF
		out[i] = b
	}
	return out
}

func randomSample(n, t int) []int {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	for i := range t {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(n-i)))
		k := i + int(j.Int64())
		perm[i], perm[k] = perm[k], perm[i]
	}
	return perm[:t]
}
