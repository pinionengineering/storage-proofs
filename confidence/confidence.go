// Package security provides detection-probability calculations for
// storage-proof challenge protocols.
package confidence

import "math"

// HypergeometricDetection returns the probability that a single challenge of
// c blocks (chosen uniformly at random from n total) catches at least one
// corrupted block, given that corruptFraction of the n blocks are corrupted.
//
// This applies to any protocol that samples a random subset of blocks per
// challenge: Ateniese S-PDP, Erway DPDP I, and Shacham-Waters.
//
// The exact formula avoids factorial overflow by computing the product form:
//
//	P(no detection) = ∏_{i=0}^{c-1} (n-t-i) / (n-i),   t = ⌊n·corruptFraction⌋
//	P(detection)    = 1 − P(no detection)
func HypergeometricDetection(n, c int, corruptFraction float64) float64 {
	if corruptFraction <= 0 || n == 0 || c == 0 {
		return 0
	}
	if corruptFraction >= 1 {
		return 1
	}
	t := int(float64(n) * corruptFraction)
	if t == 0 {
		return 0
	}
	if c > n {
		c = n
	}
	pNone := 1.0
	for i := range c {
		num := n - t - i
		if num <= 0 {
			return 1
		}
		pNone *= float64(num) / float64(n-i)
	}
	return 1 - pNone
}

// CumulativeDetection returns the probability of catching corruption in at
// least one of rounds independent challenge rounds, given a per-round
// detection probability of perRound.
func CumulativeDetection(perRound float64, rounds int) float64 {
	if perRound <= 0 || rounds == 0 {
		return 0
	}
	if perRound >= 1 {
		return 1
	}
	return 1 - math.Pow(1-perRound, float64(rounds))
}

// MinDetectableFraction returns the smallest corruption fraction that would be
// caught with at least the given confidence level after the specified number of
// challenge rounds, each sampling c blocks from n total.
//
// Uses binary search over the corruption fraction. Returns 1 if no fraction
// achieves the target confidence (e.g. too few rounds or blocks challenged).
func MinDetectableFraction(n, c, rounds int, targetConfidence float64) float64 {
	lo, hi := 0.0, 1.0
	for range 64 {
		mid := (lo + hi) / 2
		cum := CumulativeDetection(HypergeometricDetection(n, c, mid), rounds)
		if cum >= targetConfidence {
			hi = mid
		} else {
			lo = mid
		}
	}
	if hi >= 1.0 {
		return 1.0
	}
	return hi
}
