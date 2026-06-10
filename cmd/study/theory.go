package main

import "math"

// harmonicSum returns H_N = Σ_{k=1}^{N} 1/k.
func harmonicSum(N int) float64 {
	h := 0.0
	for k := 1; k <= N; k++ {
		h += 1.0 / float64(k)
	}
	return h
}

// extractionProofsExpected returns the expected number of proofs needed to
// reach a full-rank linear system for extraction, using the generalized
// coupon collector formula:
//
//	E[proofs] = N·H_N / L
//
// where N is the number of unknowns (file blocks for SW; encoded blocks for
// BJO), L is the number of blocks constrained per proof, and H_N is the N-th
// harmonic number. Each proof contributes one linear equation over Z_P; with
// random challenge coefficients the system becomes full-rank as soon as every
// unknown appears in at least one equation (the coverage event), which is the
// coupon-collector problem with L coupons drawn per round.
func extractionProofsExpected(N, L int) float64 {
	if L <= 0 || N <= 0 {
		return 0
	}
	return float64(N) * harmonicSum(N) / float64(L)
}

// bjoEncodedBlocks returns the total number of encoded blocks BJO stores for
// a file of n blocks with the given outer RS parameters.
func bjoEncodedBlocks(n, outerN, outerK int) int {
	stripes := (n + outerK - 1) / outerK
	return stripes * outerN
}

// hypergeometricDetectionProb returns the probability of detecting corruption
// in one challenge when N total blocks exist, C are challenged, and t are corrupt.
// Uses the exact hypergeometric formula P = 1 - C(N-t, C) / C(N, C).
func hypergeometricDetectionProb(N, C, t int) float64 {
	if t <= 0 || C <= 0 || N <= 0 {
		return 0
	}
	if N-t < C {
		return 1 // cannot fill challenge without sampling a corrupt block
	}
	ratio := 1.0
	for i := range C {
		ratio *= float64(N-t-i) / float64(N-i)
	}
	return 1 - ratio
}

// tagTimeScale returns the relative theoretical cost for tagging N blocks.
// Erway is O(N log N) due to skip-list construction; all others are O(N).
func tagTimeScale(scheme string, N int) float64 {
	if scheme == "Erway" {
		return float64(N) * math.Log2(float64(N)+1)
	}
	return float64(N)
}

// proveTimeScale returns the relative theoretical prove cost with challenge size C.
// BJO is O(1); Erway is O(C log N); others are O(C).
func proveTimeScale(scheme string, C, N int) float64 {
	switch scheme {
	case "BJO":
		return 1
	case "Erway":
		return float64(C) * math.Log2(float64(N)+1)
	default:
		return float64(C)
	}
}

// verifyTimeScale returns the relative theoretical verify cost.
// Ateniese: O(C) — CheckProof loops C times computing h(W)^{a_j} mod N.
// Erway: O(C log N) — C skip-list path traversals (O(log N) hashes each) plus
//
//	C RSA mod-exps; the hash traversal dominates the log N factor.
//
// SW-Pub: O(1) — two pairing operations regardless of C.
// BJO: O(1) — single MAC verify.
// SW-Priv: O(C).
func verifyTimeScale(scheme string, C, N int) float64 {
	switch scheme {
	case "BJO":
		return 1
	case "SW-Pub":
		// 2 pairings (constant) + C G1 scalar mults for ∑ νᵢH(Wᵢ)
		return float64(C)
	case "Erway":
		return float64(C) * math.Log2(float64(N)+1)
	default: // Ateniese, SW-Priv
		return float64(C)
	}
}

// keyTimeScale returns the relative theoretical setup cost for RSA key sizes.
// Ateniese tags use the private key d (~2k bits) as the exponent → O(k³).
// Erway tags use SHA-256(block) (fixed 256-bit exponent) → O(k²).
func keyTimeScale(scheme string, keyBits int) float64 {
	k := float64(keyBits)
	if scheme == "Erway" {
		return k * k
	}
	return k * k * k
}

// scaleTheory fits the theory shape to all measured points via least-squares.
// It finds α = Σ(f(xᵢ)·yᵢ) / Σ(f(xᵢ)²) so the curve isn't dominated by
// the first point where constant overhead inflates the baseline.
func scaleTheory(measured []Point, scale func(x float64) float64) []Point {
	if len(measured) == 0 {
		return nil
	}
	var num, den float64
	for _, p := range measured {
		f := scale(p.X)
		num += f * p.Y
		den += f * f
	}
	if den == 0 {
		return nil
	}
	alpha := num / den
	pts := make([]Point, len(measured))
	for i, p := range measured {
		pts[i] = Point{X: p.X, Y: alpha * scale(p.X)}
	}
	return pts
}

// challengeBytesFormula returns the theoretical challenge binary size in bytes.
func challengeBytesFormula(scheme string, C, keyBits, swPLen int) int {
	switch scheme {
	case "Ateniese":
		// Constant: N(4) + SuiteID(1) + C(4) + K1(16) + K2(16) + Gs(2*keyBits/8)
		// Gs is an element of Z_N where N=p·q, each prime keyBits bits → N is 2*keyBits bits.
		return 2*keyBits/8 + 41
	case "Erway":
		// Constant: SuiteID(1) + Seed(32) + C(4) + N(4) = 41 bytes (seed-based compact challenge)
		return 41
	case "SW-Priv":
		// Constant: SuiteID(1) + Seed(32) + C(4) + N(4) = 41 bytes (seed-based compact challenge)
		return 41
	case "SW-Pub":
		// Constant: SuiteID(1) + Seed(32) + C(4) + N(4) = 41 bytes (seed-based compact challenge)
		return 41
	case "BJO":
		// Constant: J(4) + Kjc(32) + U(4)
		return 4 + 32 + 4
	}
	return 0
}

// proofBytesFormula returns the theoretical proof binary size in bytes.
// N is the number of blocks (needed for Erway's skip-list path length).
func proofBytesFormula(scheme string, C, keyBits, N, swPLen, swS, bjoP int) int {
	switch scheme {
	case "Ateniese":
		// Constant: T(2*keyBits/8) + Rho(32)
		return 2*keyBits/8 + 32
	case "Erway":
		// Per challenged block: tag(2*keyBits/8) + path steps × 45B
		// Path length ≈ 2·log₂(N) steps; each step: Level(4)+Rank(4)+Right(1)+SibLabel(32)+Q(4)=45B
		// M accumulates C unreduced products of 128-bit coeff × 256-bit hash → up to C×48 bytes
		steps := int(2 * math.Log2(float64(N)+1))
		return C*(2*keyBits/8+steps*45) + C*48
	case "SW-Priv":
		// Constant: sigma(swPLen) + mu(swS × swPLen)
		return swPLen + swS*swPLen
	case "SW-Pub":
		// Constant: sigma(64-byte G1) + mu(swS × 32-byte scalar)
		return 64 + swS*32
	case "BJO":
		// Constant: Mj + Qj byte slices (both proportional to bjoP)
		return bjoP + bjoP + 16
	}
	return 0
}
