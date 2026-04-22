// pdpstats tests that the PDP implementation matches the theoretical statistical
// properties described in the paper.
//
// Two core properties are verified:
//
//  1. Completeness: a server holding all correct blocks passes every challenge.
//     Expected pass rate: 1.000.
//
//  2. Soundness (single corrupt block): when one of n blocks is corrupted, the
//     probability of detecting it in a single challenge of C blocks is exactly
//     C/n (the probability that the PRP selects the bad block). After k
//     independent challenges, cumulative detection probability is 1−(1−C/n)^k.
//
// Detection probability derivation:
//
//	The BuildPRP selects a uniformly random subset of C blocks from n. The bad
//	block occupies exactly 1 of the n positions. The probability it is included
//	in the challenged set is C/n (hypergeometric argument: first block of the
//	permutation lands on the bad one with probability 1/n, times C draws without
//	replacement, giving C/n exactly). If the bad block is selected, the server
//	cannot produce a correct μ, so CheckProof returns false with overwhelming
//	cryptographic probability.
//
// Statistical test: for each (n, C) pair and a corpus of T trials, the observed
// detection count D follows Binomial(T, p) where p = C/n. Under the normal
// approximation, (D − T·p) / √(T·p·(1−p)) is approximately N(0,1). We flag a
// failure when |z| > zFail (≈1-in-10000 chance of false alarm per scenario).
package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"os"

	"github.com/pinionengineering/storage-proofs/pdp"
)

const (
	keyBits  = 128  // small for speed; use ≥1024 in production
	nBlocks  = 100  // total number of file blocks
	zFail    = 4.0  // |z| threshold for declaring a statistical mismatch
)

// result holds the outcome of one statistical scenario.
type result struct {
	label    string
	trials   int
	detected int
	pTheory  float64
}

func (r result) zScore() float64 {
	if r.trials == 0 {
		return 0
	}
	exp := float64(r.trials) * r.pTheory
	variance := exp * (1 - r.pTheory)
	if variance == 0 {
		if float64(r.detected) == exp {
			return 0
		}
		return math.Inf(1)
	}
	return (float64(r.detected) - exp) / math.Sqrt(variance)
}

func (r result) pass() bool {
	z := r.zScore()
	return math.Abs(z) <= zFail
}

func (r result) String() string {
	obs := float64(r.detected) / float64(r.trials)
	z := r.zScore()
	status := "PASS"
	if !r.pass() {
		status = "FAIL"
	}
	return fmt.Sprintf("%-52s  obs=%.4f  theory=%.4f  z=%+.2f  [%s]",
		r.label, obs, r.pTheory, z, status)
}

// setup generates a key pair, n blocks, and their tags. Returns the honest
// block set and a corrupted copy where blocks[badIdx] has been replaced.
func setup(n int) (pk *pdp.PublicKey, sk *pdp.SecretKey, honest [][]byte, tags []*pdp.Tag, badIdx int, err error) {
	pk, sk, err = pdp.KeyGen(keyBits)
	if err != nil {
		return
	}

	honest = make([][]byte, n)
	tags = make([]*pdp.Tag, n)
	for i := range n {
		honest[i] = make([]byte, 256)
		if _, err = rand.Read(honest[i]); err != nil {
			return
		}
		tags[i], err = pdp.SuiteV1.TagBlock(pk, sk, honest[i], uint64(i))
		if err != nil {
			return
		}
	}

	// Pick a random block index to corrupt.
	bidx, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return
	}
	badIdx = int(bidx.Int64())
	return
}

// makeChallenge builds a fresh Challenge and returns the client secret s.
func makeChallenge(pk *pdp.PublicKey, c int) (secret *big.Int, chal *pdp.Challenge, err error) {
	secret, err = rand.Int(rand.Reader, pk.N)
	if err != nil {
		return
	}
	Gs := new(big.Int).Exp(pk.G, secret, pk.N)

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	if _, err = rand.Read(k1); err != nil {
		return
	}
	if _, err = rand.Read(k2); err != nil {
		return
	}

	chal = &pdp.Challenge{
		SuiteID: pdp.SuiteV1.ID(),
		C:       c,
		K1:      k1,
		K2:      k2,
		Gs:      Gs,
	}
	return
}

// runOne executes a single challenge-response cycle and returns whether the
// verifier accepted the proof.
func runOne(pk *pdp.PublicKey, sk *pdp.SecretKey, blocks [][]byte, tags []*pdp.Tag, c int) (bool, error) {
	secret, chal, err := makeChallenge(pk, c)
	if err != nil {
		return false, err
	}
	proof, err := pdp.SuiteV1.GenProof(pk, blocks, chal, tags)
	if err != nil {
		return false, err
	}
	return pdp.SuiteV1.CheckProof(pk, sk, secret, tags, chal, proof)
}

func main() {
	fmt.Println("PDP Statistical Properties Test")
	fmt.Println("================================")
	fmt.Printf("Key bits: %d  |  File blocks: %d\n\n", keyBits, nBlocks)

	pk, sk, honest, tags, badIdx, err := setup(nBlocks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		os.Exit(1)
	}

	// Build corrupted block set: all blocks honest except badIdx.
	corrupt := make([][]byte, nBlocks)
	copy(corrupt, honest)
	corrupt[badIdx] = make([]byte, 256)
	if _, err = rand.Read(corrupt[badIdx]); err != nil {
		fmt.Fprintf(os.Stderr, "rand: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Corrupted block index: %d\n\n", badIdx)

	var results []result
	anyFail := false

	// -------------------------------------------------------------------------
	// Scenario 1: Honest server — every challenge must pass.
	// -------------------------------------------------------------------------
	fmt.Println("── Scenario 1: Completeness (honest server, all blocks correct) ──")
	{
		const trials = 200
		challengeSizes := []int{1, 5, 10, 25, 50, nBlocks}
		for _, c := range challengeSizes {
			detected := 0
			for t := range trials {
				_ = t
				ok, err := runOne(pk, sk, honest, tags, c)
				if err != nil {
					fmt.Fprintf(os.Stderr, "runOne: %v\n", err)
					os.Exit(1)
				}
				if !ok {
					detected++ // a failure is a "detection" against theory=0
				}
			}
			r := result{
				label:   fmt.Sprintf("n=%d  C=%-3d  trials=%d  honest", nBlocks, c, trials),
				trials:  trials,
				detected: detected,
				pTheory: 0.0, // no failures expected
			}
			// For completeness, any failure is a hard error regardless of z-score.
			if detected > 0 {
				fmt.Printf("  %s  *** HARD FAIL: %d unexpected rejection(s) ***\n", r, detected)
				anyFail = true
			} else {
				fmt.Printf("  %s\n", r)
			}
			results = append(results, r)
		}
	}
	fmt.Println()

	// -------------------------------------------------------------------------
	// Scenario 2: Single corrupted block — detection rate must equal C/n.
	// -------------------------------------------------------------------------
	fmt.Printf("── Scenario 2: Soundness (block %d/%d corrupted) ──\n", badIdx, nBlocks)
	fmt.Println("  Theory: P(detect | C, n) = C/n")
	{
		type row struct {
			c      int
			trials int
		}
		rows := []row{
			{1, 3000},
			{5, 3000},
			{10, 2000},
			{20, 2000},
			{50, 1000},
			{nBlocks, 500},
		}
		for _, rw := range rows {
			detected := 0
			for t := range rw.trials {
				_ = t
				ok, err := runOne(pk, sk, corrupt, tags, rw.c)
				if err != nil {
					fmt.Fprintf(os.Stderr, "runOne: %v\n", err)
					os.Exit(1)
				}
				if !ok {
					detected++
				}
			}
			pTheory := float64(rw.c) / float64(nBlocks)
			r := result{
				label:    fmt.Sprintf("n=%d  C=%-3d  trials=%d  corrupt", nBlocks, rw.c, rw.trials),
				trials:   rw.trials,
				detected: detected,
				pTheory:  pTheory,
			}
			fmt.Printf("  %s\n", r)
			if !r.pass() {
				anyFail = true
			}
			results = append(results, r)
		}
	}
	fmt.Println()

	// -------------------------------------------------------------------------
	// Scenario 3: Cumulative detection — k repeated challenges.
	// P(detected within k challenges) = 1 − (1 − C/n)^k
	// -------------------------------------------------------------------------
	const cumC = 10 // challenge size for cumulative test
	fmt.Printf("── Scenario 3: Cumulative detection (C=%d, n=%d, 1 corrupt block) ──\n", cumC, nBlocks)
	fmt.Println("  Theory: P(detect within k challenges) = 1 − (1 − C/n)^k")
	{
		pPerRound := float64(cumC) / float64(nBlocks)
		type krow struct {
			k      int
			trials int
		}
		krows := []krow{
			{1, 2000},
			{3, 1500},
			{5, 1000},
			{10, 800},
			{20, 500},
			{50, 300},
		}
		for _, kr := range krows {
			detected := 0
			for t := range kr.trials {
				_ = t
				// Run k challenges; detect if any fails.
				caught := false
				for round := range kr.k {
					_ = round
					ok, err := runOne(pk, sk, corrupt, tags, cumC)
					if err != nil {
						fmt.Fprintf(os.Stderr, "runOne: %v\n", err)
						os.Exit(1)
					}
					if !ok {
						caught = true
						break
					}
				}
				if caught {
					detected++
				}
			}
			pTheory := 1 - math.Pow(1-pPerRound, float64(kr.k))
			r := result{
				label:    fmt.Sprintf("n=%d  C=%d  k=%-3d  trials=%d", nBlocks, cumC, kr.k, kr.trials),
				trials:   kr.trials,
				detected: detected,
				pTheory:  pTheory,
			}
			fmt.Printf("  %s\n", r)
			if !r.pass() {
				anyFail = true
			}
			results = append(results, r)
		}
	}
	fmt.Println()

	// -------------------------------------------------------------------------
	// Summary
	// -------------------------------------------------------------------------
	passed := 0
	failed := 0
	for _, r := range results {
		if r.pTheory == 0 {
			continue // honest-server rows evaluated separately above
		}
		if r.pass() {
			passed++
		} else {
			failed++
		}
	}
	fmt.Printf("Statistical scenarios: %d passed, %d failed (|z| threshold = %.1f)\n", passed, failed, zFail)
	if anyFail {
		fmt.Println("RESULT: FAIL — implementation does not match theoretical statistical properties.")
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS — all observations are consistent with theoretical predictions.")
}
