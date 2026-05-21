package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"syscall"

	blockspkg "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	lineAteniese "github.com/pinionengineering/storage-proofs/line/ateniese"
	lineBJO "github.com/pinionengineering/storage-proofs/line/bjo"
	lineErway "github.com/pinionengineering/storage-proofs/line/erway"
	lineSW "github.com/pinionengineering/storage-proofs/line/sw"
	lineSwPub "github.com/pinionengineering/storage-proofs/line/swpub"
	pdpateniese "github.com/pinionengineering/storage-proofs/pdp/ateniese"
	pdperway "github.com/pinionengineering/storage-proofs/pdp/erway"
	porbjo "github.com/pinionengineering/storage-proofs/por/bjo"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

// setupTagger combines line.Tagger and line.SetupProducer, which all scheme
// taggers implement after TagBlocks has been called.
type setupTagger interface {
	line.Tagger
	line.SetupProducer
}

// schemeSpec describes one storage-proof scheme using only the line interfaces.
type schemeSpec struct {
	name, color string
	newTagger   func(keyBits, chalSize int) (setupTagger, error)
	chalFactory line.ChallengerFactory
	provFactory line.ProverFactory
}

var schemes = []schemeSpec{
	{
		name:  "Ateniese",
		color: "#3b82f6",
		newTagger: func() func(int, int) (setupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (setupTagger, error){}
			return func(keyBits, _ int) (setupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[keyBits]
				if !ok {
					pk, sk, err := pdpateniese.KeyGen(keyBits)
					if err != nil {
						return nil, err
					}
					fn = func() (setupTagger, error) {
						return lineAteniese.NewTagger(pk, sk, suite.SuiteV1), nil
					}
					cache[keyBits] = fn
				}
				return fn()
			}
		}(),
		chalFactory: lineAteniese.NewChallengerFactory(),
		provFactory: lineAteniese.NewProverFactory(),
	},
	{
		name:  "Erway",
		color: "#ef4444",
		newTagger: func() func(int, int) (setupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (setupTagger, error){}
			return func(keyBits, _ int) (setupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[keyBits]
				if !ok {
					pk, err := pdperway.KeyGen(keyBits)
					if err != nil {
						return nil, err
					}
					fn = func() (setupTagger, error) {
						return lineErway.NewTagger(pk, suite.SuiteV1), nil
					}
					cache[keyBits] = fn
				}
				return fn()
			}
		}(),
		chalFactory: lineErway.NewChallengerFactory(),
		provFactory: lineErway.NewProverFactory(suite.SuiteV1),
	},
	{
		name:  "SW-Priv",
		color: "#f59e0b",
		newTagger: func() func(int, int) (setupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (setupTagger, error){}
			return func(_, chalSize int) (setupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[chalSize]
				if !ok {
					sk, err := porsw.KeyGen(&porsw.Params{S: swS, L: chalSize, P: swP})
					if err != nil {
						return nil, err
					}
					fn = func() (setupTagger, error) {
						return lineSW.NewTagger(sk, suite.SuiteV1), nil
					}
					cache[chalSize] = fn
				}
				return fn()
			}
		}(),
		chalFactory: lineSW.NewChallengerFactory(),
		provFactory: lineSW.NewProverFactory(),
	},
	{
		name:  "BJO",
		color: "#10b981",
		newTagger: func() func(int, int) (setupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (setupTagger, error){}
			return func(_, chalSize int) (setupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[chalSize]
				if !ok {
					mk, err := porbjo.KeyGen(&porbjo.Params{
						V: chalSize, W: bjoW, Q: bjoQ, P: bjoP,
						OuterN: bjoOuterN, OuterK: bjoOuterK,
					})
					if err != nil {
						return nil, err
					}
					fn = func() (setupTagger, error) {
						return lineBJO.NewTagger(mk, suite.SuiteV1), nil
					}
					cache[chalSize] = fn
				}
				return fn()
			}
		}(),
		chalFactory: lineBJO.NewChallengerFactory(),
		provFactory: lineBJO.NewProverFactory(suite.SuiteV1),
	},
	{
		name:  "SW-Pub",
		color: "#8b5cf6",
		newTagger: func() func(int, int) (setupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (setupTagger, error){}
			return func(_, chalSize int) (setupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[chalSize]
				if !ok {
					ps, err := porsw.NewPubScheme(swS, chalSize)
					if err != nil {
						return nil, err
					}
					fn = func() (setupTagger, error) {
						return lineSwPub.NewTagger(ps, suite.SuiteV1), nil
					}
					cache[chalSize] = fn
				}
				return fn()
			}
		}(),
		chalFactory: lineSwPub.NewChallengerFactory(),
		provFactory: lineSwPub.NewProverFactory(),
	},
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
	tagger, err := sch.newTagger(p.KeyBits, p.ChalSize)
	if err != nil {
		return Metrics{}, fmt.Errorf("%s newTagger: %w", sch.name, err)
	}

	// Time TagBlocks (server setup).
	setupTime, err := timeOp(benchReps, func() error { _, e := tagger.TagBlocks(store); return e })
	if err != nil {
		return Metrics{}, fmt.Errorf("%s tag: %w", sch.name, err)
	}
	if _, err = tagger.TagBlocks(store); err != nil { // final call for consistent state
		return Metrics{}, fmt.Errorf("%s tag final: %w", sch.name, err)
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

	challenger, err := sch.chalFactory.NewChallenger(clientSetup, p.ChalSize)
	if err != nil {
		return Metrics{}, err
	}
	prover, err := sch.provFactory.NewProver(proverSetup, encoded)
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
