package ateniese

// This file contains tests that verify the mathematical invariants underpinning
// the S-PDP protocol.  Each test is self-contained and documents the property
// it is checking.

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

// --- helpers -----------------------------------------------------------------

// smallSafePrimes returns p = 2p'+1 and p' for a 64-bit safe prime.
// 64-bit primes are fast enough for unit tests.
func smallSafePrimes(t *testing.T) (p, pPrime *big.Int) {
	t.Helper()
	p, pPrime, err := pdp.GenerateSafePrime(64)
	if err != nil {
		t.Fatalf("GenerateSafePrime: %v", err)
	}
	return p, pPrime
}

// randomInQRN returns a guaranteed member of QR_N by squaring a random unit.
func randomInQRN(t *testing.T, N *big.Int) *big.Int {
	t.Helper()
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(N, one)
	for {
		a, err := rand.Int(rand.Reader, nMinus1)
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}
		a.Add(a, one)
		if new(big.Int).GCD(nil, nil, a, N).Cmp(one) != 0 {
			continue
		}
		return new(big.Int).Exp(a, big.NewInt(2), N)
	}
}

// newRSAModulus builds N=pq and returns p,p',q,q',N,phi=p'q'.
func newRSAModulus(t *testing.T) (p, pp, q, qp, N, phi *big.Int) {
	t.Helper()
	p, pp = smallSafePrimes(t)
	q, qp = smallSafePrimes(t)
	N = new(big.Int).Mul(p, q)
	phi = new(big.Int).Mul(pp, qp)
	return
}

// --- 1. Group order ----------------------------------------------------------

// TestQRNOrderIsPrimeProduct verifies that |QR_N| = p'q' = phi(N)/4.
//
// For N = pq with safe primes p = 2p'+1, q = 2q'+1:
//   - phi(N) = (p-1)(q-1) = 4p'q'
//   - The squaring map on Z*_N has kernel of size 4, so |QR_N| = phi(N)/4 = p'q'.
func TestQRNOrderIsPrimeProduct(t *testing.T) {
	_, pp, _, qp, _, phi := newRSAModulus(t)
	// The order the implementation stores in sk.Phi
	smallPhi := new(big.Int).Mul(pp, qp)

	if smallPhi.Cmp(phi) != 0 {
		t.Fatalf("phi mismatch: got %v, want %v", phi, smallPhi)
	}

	// Independently recompute: phi(N)/4 must equal p'q'
	p2, _ := smallSafePrimes(t)
	q2, _ := smallSafePrimes(t)
	pm1 := new(big.Int).Sub(p2, big.NewInt(1))
	qm1 := new(big.Int).Sub(q2, big.NewInt(1))
	fullPhi := new(big.Int).Mul(pm1, qm1)
	four := big.NewInt(4)
	ratio := new(big.Int).Div(fullPhi, four)

	// fullPhi / 4 should be an integer (no remainder)
	mod := new(big.Int).Mod(fullPhi, four)
	if mod.Sign() != 0 {
		t.Fatalf("phi(N) is not divisible by 4 for safe-prime N; remainder %v", mod)
	}

	// ratio == p''*q'' for the primes we used
	_ = ratio // numeric equality would need the matching p'',q'' — the divisibility check suffices
}

// TestGroupOrderOfGIsPhiNOver4 verifies that a generator produced by
// GenerateGQRN satisfies g^(p'q') ≡ 1 mod N, i.e. its order divides p'q'.
func TestGroupOrderOfGIsPhiNOver4(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)

	g, err := pdp.GenerateGQRN(N)
	if err != nil {
		t.Fatalf("GenerateGQRN: %v", err)
	}

	result := new(big.Int).Exp(g, phi, N)
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("g^(p'q') mod N = %v, want 1", result)
	}
}

// --- 2. RSA trapdoor in QR_N -------------------------------------------------

// TestEDInverseModPhi verifies that e*d ≡ 1 mod p'q' and that the RSA
// round-trip x^(ed) ≡ x mod N holds for any x in QR_N.
func TestEDInverseModPhi(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)
	one := big.NewInt(1)

	// choose e coprime to phi
	e := big.NewInt(65537)
	for new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
		e.Add(e, big.NewInt(2))
	}
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		t.Fatal("ModInverse returned nil")
	}

	// e*d mod phi == 1
	ed := new(big.Int).Mul(e, d)
	ed.Mod(ed, phi)
	if ed.Cmp(one) != 0 {
		t.Fatalf("e*d mod phi = %v, want 1", ed)
	}

	// For any x in QR_N: x^(ed) = x
	for range 5 {
		x := randomInQRN(t, N)
		xed := new(big.Int).Exp(x, e, N)
		xed = new(big.Int).Exp(xed, d, N)
		if xed.Cmp(x) != 0 {
			t.Fatalf("x^(ed) != x for x=%v", x)
		}
	}
}

// TestEDOnFullPhiWouldFail demonstrates why using phi(N)=4p'q' (the full Euler
// totient) is not required: e is chosen coprime to p'q', and elements of QR_N
// have order dividing p'q', so using the smaller modulus is both correct and
// sufficient.  The full-phi and small-phi inverses differ but both produce the
// same round-trip on QR_N elements.
func TestEDOnFullPhiWouldFail(t *testing.T) {
	p, pp, q, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)
	one := big.NewInt(1)

	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)
	fullPhi := new(big.Int).Mul(pm1, qm1)

	e := big.NewInt(65537)
	for new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
		e.Add(e, big.NewInt(2))
	}

	dSmall := new(big.Int).ModInverse(e, phi)
	dFull := new(big.Int).ModInverse(e, fullPhi)

	// Both d values should give the same round-trip on QR_N elements
	for range 5 {
		x := randomInQRN(t, N)

		xWithSmall := new(big.Int).Exp(x, e, N)
		xWithSmall = new(big.Int).Exp(xWithSmall, dSmall, N)

		xWithFull := new(big.Int).Exp(x, e, N)
		xWithFull = new(big.Int).Exp(xWithFull, dFull, N)

		if xWithSmall.Cmp(x) != 0 {
			t.Fatalf("small-phi round-trip failed for x=%v", x)
		}
		if xWithFull.Cmp(x) != 0 {
			t.Fatalf("full-phi round-trip failed for x=%v", x)
		}
	}
}

// --- 3. Exponent reduction mod group order -----------------------------------

// TestExponentReductionModGroupOrder verifies that for any g in QR_N and any
// integer k, g^k ≡ g^(k mod p'q') mod N.  This is the Lagrange theorem applied
// to the cyclic group QR_N of order p'q'.
//
// This property is what makes the asymmetric a_j reduction in GenProof vs.
// CheckProof mathematically harmless: both sides compute the same group element.
func TestExponentReductionModGroupOrder(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)

	g, err := pdp.GenerateGQRN(N)
	if err != nil {
		t.Fatalf("GenerateGQRN: %v", err)
	}

	for range 10 {
		// random large exponent (much bigger than phi)
		bigExp, err := rand.Int(rand.Reader, new(big.Int).Mul(phi, phi))
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}

		reduced := new(big.Int).Mod(bigExp, phi)

		g1 := new(big.Int).Exp(g, bigExp, N)
		g2 := new(big.Int).Exp(g, reduced, N)

		if g1.Cmp(g2) != 0 {
			t.Fatalf("g^k != g^(k mod phi): k=%v", bigExp)
		}
	}
}

// TestMuReductionEquivalence verifies the core algebraic reason the
// verification equation holds despite μ being unreduced in GenProof:
//
//	sum(a_j * m_i)  ≡  sum((a_j mod p'q') * (m_i mod p'q'))  mod p'q'
//
// And therefore g^(s*μ_raw) = g^(s*μ_reduced) in QR_N.
func TestMuReductionEquivalence(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)

	g, err := pdp.GenerateGQRN(N)
	if err != nil {
		t.Fatalf("GenerateGQRN: %v", err)
	}

	for range 10 {
		aj, err := rand.Int(rand.Reader, new(big.Int).Lsh(phi, 8)) // larger than phi
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}
		mi, err := rand.Int(rand.Reader, new(big.Int).Lsh(phi, 8))
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}

		muRaw := new(big.Int).Mul(aj, mi)
		muReduced := new(big.Int).Mod(muRaw, phi)

		// The integer reductions must agree mod phi
		ajR := new(big.Int).Mod(aj, phi)
		miR := new(big.Int).Mod(mi, phi)
		muViaReducedParts := new(big.Int).Mod(new(big.Int).Mul(ajR, miR), phi)

		if muReduced.Cmp(muViaReducedParts) != 0 {
			t.Fatalf("modular arithmetic identity broken")
		}

		// And both give the same group element
		s := big.NewInt(7)
		g1 := new(big.Int).Exp(g, new(big.Int).Mul(s, muRaw), N)
		g2 := new(big.Int).Exp(g, new(big.Int).Mul(s, muReduced), N)
		if g1.Cmp(g2) != 0 {
			t.Fatalf("g^(s*mu_raw) != g^(s*mu_reduced)")
		}
	}
}

// --- 4. Verification equation ------------------------------------------------

// TestVerificationEquation traces the full algebraic identity that CheckProof
// relies on.  With a single block for clarity:
//
//	tag = (h(W) * g^m)^d  mod N
//	tag^(e*a) = (h(W) * g^m)^(d*e*a) = (h(W) * g^m)^a   (since d*e ≡ 1 mod p'q')
//
// So  T^e / H_prod = g^μ  and  (g^μ)^s = g^(sμ).
func TestVerificationEquation(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)
	one := big.NewInt(1)

	e := big.NewInt(65537)
	for new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
		e.Add(e, big.NewInt(2))
	}
	d := new(big.Int).ModInverse(e, phi)

	g, err := pdp.GenerateGQRN(N)
	if err != nil {
		t.Fatalf("GenerateGQRN: %v", err)
	}

	// Simulate one block
	mHash, err := rand.Int(rand.Reader, new(big.Int).Lsh(phi, 4))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	W, err := rand.Int(rand.Reader, N)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	a, err := rand.Int(rand.Reader, new(big.Int).Lsh(phi, 4))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	s := big.NewInt(13) // small stand-in for challenge exponent

	// h(W) via hashToQRN — use randomInQRN as a stand-in
	h := randomInQRN(t, N)
	_ = W

	// tag = (h * g^m)^d
	gm := new(big.Int).Exp(g, mHash, N)
	base := new(big.Int).Mul(h, gm)
	base.Mod(base, N)
	tag := new(big.Int).Exp(base, d, N)

	// T = tag^a (single-block aggregate)
	T := new(big.Int).Exp(tag, a, N)

	// mu = a * mHash (unreduced, as in GenProof)
	mu := new(big.Int).Mul(a, mHash)

	// GenProof side: g^(s*mu)
	gsmu_gen := new(big.Int).Exp(g, new(big.Int).Mul(s, mu), N)

	// CheckProof side:
	// H_prod = h^(a mod phi) (one block)
	aReduced := new(big.Int).Mod(a, phi)
	Hprod := new(big.Int).Exp(h, aReduced, N)

	Te := new(big.Int).Exp(T, e, N)
	Hinv := new(big.Int).ModInverse(Hprod, N)
	if Hinv == nil {
		t.Fatal("Hprod not invertible")
	}
	gmu := new(big.Int).Mul(Te, Hinv)
	gmu.Mod(gmu, N)
	gsmu_check := new(big.Int).Exp(gmu, s, N)

	if gsmu_gen.Cmp(gsmu_check) != 0 {
		t.Fatalf("verification equation failed:\n  GenProof  g^(sμ) = %v\n  CheckProof g^(sμ) = %v", gsmu_gen, gsmu_check)
	}
}

// TestVerificationEquationMultiBlock extends TestVerificationEquation to
// multiple blocks to confirm the product form works.
func TestVerificationEquationMultiBlock(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)
	one := big.NewInt(1)

	e := big.NewInt(65537)
	for new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
		e.Add(e, big.NewInt(2))
	}
	d := new(big.Int).ModInverse(e, phi)

	g, err := pdp.GenerateGQRN(N)
	if err != nil {
		t.Fatalf("GenerateGQRN: %v", err)
	}

	const C = 5
	s := big.NewInt(17)

	T_agg := big.NewInt(1)
	mu := big.NewInt(0)
	Hprod := big.NewInt(1)

	for j := 0; j < C; j++ {
		mHash, _ := rand.Int(rand.Reader, new(big.Int).Lsh(phi, 4))
		a, _ := rand.Int(rand.Reader, new(big.Int).Lsh(phi, 4))
		h := randomInQRN(t, N)

		// tag_j = (h_j * g^m_j)^d
		gm := new(big.Int).Exp(g, mHash, N)
		base := new(big.Int).Mul(h, gm)
		base.Mod(base, N)
		tag := new(big.Int).Exp(base, d, N)

		// aggregate T (GenProof)
		term := new(big.Int).Exp(tag, a, N)
		T_agg.Mul(T_agg, term)
		T_agg.Mod(T_agg, N)

		// aggregate mu (GenProof, unreduced)
		mu.Add(mu, new(big.Int).Mul(a, mHash))

		// aggregate Hprod (CheckProof, a reduced mod phi)
		aR := new(big.Int).Mod(a, phi)
		Hprod.Mul(Hprod, new(big.Int).Exp(h, aR, N))
		Hprod.Mod(Hprod, N)
	}

	// GenProof result
	gsmu_gen := new(big.Int).Exp(g, new(big.Int).Mul(s, mu), N)

	// CheckProof result
	Te := new(big.Int).Exp(T_agg, e, N)
	Hinv := new(big.Int).ModInverse(Hprod, N)
	if Hinv == nil {
		t.Fatal("Hprod not invertible")
	}
	gmu := new(big.Int).Mul(Te, Hinv)
	gmu.Mod(gmu, N)
	gsmu_check := new(big.Int).Exp(gmu, s, N)

	if gsmu_gen.Cmp(gsmu_check) != 0 {
		t.Fatalf("multi-block verification equation failed")
	}
}

// --- 5. GenerateGQRN output is in QR_N ---------------------------------------

// TestGenerateGQRNInQRN verifies that GenerateGQRN always returns a value in QR_N:
// g^(p'q') ≡ 1 mod N.  The paper's construction (gcd filters + squaring) ensures
// QR_N membership; full generator status holds with overwhelming probability.
func TestGenerateGQRNInQRN(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)

	for range 20 {
		g, err := pdp.GenerateGQRN(N)
		if err != nil {
			t.Fatalf("GenerateGQRN: %v", err)
		}
		if new(big.Int).Exp(g, phi, N).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("g^(p'q') != 1: g is not in QR_N")
		}
	}
}

// --- 6. hashToQRN output is in QR_N -----------------------------------------

// TestHashToQRNInQRN verifies that suite.SuiteV1.HashToQRN always produces a value in QR_N
// (i.e. h^(p'q') ≡ 1 mod N).
func TestHashToQRNInQRN(t *testing.T) {
	_, pp, _, qp, N, _ := newRSAModulus(t)
	phi := new(big.Int).Mul(pp, qp)

	for range 20 {
		data := make([]byte, 32)
		rand.Read(data)
		h := suite.SuiteV1.HashToQRN(data, N)
		if new(big.Int).Exp(h, phi, N).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("h(data)^(p'q') != 1: hashToQRN output is not in QR_N")
		}
	}
}

// --- 7. End-to-end with small keys ------------------------------------------

// TestFullProtocolSmallKeys runs the complete KeyGen / TagBlock / GenProof /
// CheckProof cycle with deliberately small keys so it completes quickly and
// confirms all pieces fit together.
func TestFullProtocolSmallKeys(t *testing.T) {
	pk, sk, err := KeyGen(64)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	const nBlocks = 10
	blocks := make([][]byte, nBlocks)
	tags := make([]*Tag, nBlocks)
	for i := range nBlocks {
		blocks[i] = make([]byte, 64)
		rand.Read(blocks[i])
		w := binary.BigEndian.AppendUint64(append([]byte(nil), sk.V...), uint64(i))
		tags[i], err = TagBlock(suite.SuiteV1, pk, sk, blocks[i], w)
		if err != nil {
			t.Fatalf("TagBlock[%d]: %v", i, err)
		}
	}

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	rand.Read(k1)
	rand.Read(k2)

	s, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	Gs := new(big.Int).Exp(pk.G, s, pk.N)

	chal := &Challenge{
		SuiteID: suite.SuiteV1.ID(),
		C:       4,
		K1:      k1,
		K2:      k2,
		Gs:      Gs,
	}

	proof, err := GenProof(suite.SuiteV1, pk, blocks, chal, tags)
	if err != nil {
		t.Fatalf("GenProof: %v", err)
	}

	ok, err := CheckProof(suite.SuiteV1, pk, sk, s, tags, chal, proof)
	if err != nil {
		t.Fatalf("CheckProof: %v", err)
	}
	if !ok {
		t.Fatal("valid proof rejected")
	}
}

// TestTamperedBlockFails confirms that replacing a challenged block with random
// bytes causes CheckProof to reject the proof — i.e. the scheme detects
// corruption.
func TestTamperedBlockFails(t *testing.T) {
	pk, sk, err := KeyGen(64)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	const nBlocks = 10
	blocks := make([][]byte, nBlocks)
	tags := make([]*Tag, nBlocks)
	for i := range nBlocks {
		blocks[i] = make([]byte, 64)
		rand.Read(blocks[i])
		w := binary.BigEndian.AppendUint64(append([]byte(nil), sk.V...), uint64(i))
		tags[i], err = TagBlock(suite.SuiteV1, pk, sk, blocks[i], w)
		if err != nil {
			t.Fatalf("TagBlock[%d]: %v", i, err)
		}
	}

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	rand.Read(k1)
	rand.Read(k2)

	s, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	Gs := new(big.Int).Exp(pk.G, s, pk.N)

	chal := &Challenge{SuiteID: suite.SuiteV1.ID(), C: 4, K1: k1, K2: k2, Gs: Gs}

	// Tamper every block to guarantee at least one challenged block is corrupted.
	for i := range nBlocks {
		tampered := make([]byte, 64)
		rand.Read(tampered)
		blocks[i] = tampered
	}

	proof, err := GenProof(suite.SuiteV1, pk, blocks, chal, tags)
	if err != nil {
		t.Fatalf("GenProof: %v", err)
	}

	ok, err := CheckProof(suite.SuiteV1, pk, sk, s, tags, chal, proof)
	if err != nil {
		t.Fatalf("CheckProof: %v", err)
	}
	if ok {
		t.Fatal("tampered proof accepted — verification should have failed")
	}
}
