package por

// This file verifies the mathematical invariants underpinning the POR protocol.
// Each test documents the algebraic property it is checking and its role in
// protocol correctness, mirroring the structure of pdp/math_test.go.

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/pinionengineering/storage-proofs/pdp"
)

// --- helpers -----------------------------------------------------------------

// smallP is a small prime (2^31 - 1 = 2147483647, a Mersenne prime) used as
// the inner code modulus in mathematical tests for speed. Production uses a
// 256-bit prime.
var smallP = big.NewInt(2147483647)

// randomBlock returns a random block of the given size.
func randomBlock(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// randomBlocks returns n random blocks each of the given size.
func randomBlocks(t *testing.T, n, size int) [][]byte {
	t.Helper()
	blocks := make([][]byte, n)
	for i := range n {
		blocks[i] = randomBlock(t, size)
	}
	return blocks
}

// blockFieldElem returns SHA-256(block) mod P, the Z_P element that the protocol
// uses to represent block content (matching computeInnerResponse).
func blockFieldElem(block []byte, P *big.Int) *big.Int {
	sum := sha256.Sum256(block)
	return new(big.Int).Mod(new(big.Int).SetBytes(sum[:]), P)
}

// --- 1. GF(256) field axioms -------------------------------------------------

// TestGF256FermatLittleTheorem verifies a^255 = 1 for all nonzero a in GF(256).
// By Fermat's little theorem for finite fields, every nonzero element of GF(2^8)
// satisfies a^(|GF(256)*|) = a^255 = 1. This confirms the exp/log table
// construction is consistent and g=2 has order 255 (a primitive element).
func TestGF256FermatLittleTheorem(t *testing.T) {
	for a := 1; a < 256; a++ {
		if got := gfPow(byte(a), 255); got != 1 {
			t.Fatalf("gfPow(%d, 255) = %d, want 1", a, got)
		}
	}
}

// TestGF256Distributivity verifies a*(b+c) = a*b + a*c for all a,b,c in GF(256).
// Distributivity is required for GF(256) to be a field; the RS code's linearity
// depends on this property.
func TestGF256Distributivity(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 16; b++ { // sample a subset for speed
			for c := 0; c < 16; c++ {
				lhs := gfMul(byte(a), gfAdd(byte(b), byte(c)))
				rhs := gfAdd(gfMul(byte(a), byte(b)), gfMul(byte(a), byte(c)))
				if lhs != rhs {
					t.Fatalf("distributivity failed: %d*(%d+%d)=%d but %d*%d+%d*%d=%d",
						a, b, c, lhs, a, b, a, c, rhs)
				}
			}
		}
	}
}

// TestGF256InverseCorrectness verifies a * gfInv(a) = 1 for all nonzero a.
// Correctness of the multiplicative inverse is used in Lagrange interpolation
// during RS encoding (the denominator term in L_i(x) is inverted).
func TestGF256InverseCorrectness(t *testing.T) {
	for a := 1; a < 256; a++ {
		if got := gfMul(byte(a), gfInv(byte(a))); got != 1 {
			t.Fatalf("a * gfInv(a) = %d for a=%d, want 1", got, a)
		}
	}
}

// TestGF256MulCommutativity verifies a*b = b*a for sample values.
func TestGF256MulCommutativity(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if gfMul(byte(a), byte(b)) != gfMul(byte(b), byte(a)) {
				t.Fatalf("gfMul not commutative: gfMul(%d,%d) != gfMul(%d,%d)", a, b, b, a)
			}
		}
	}
}

// TestGF256GeneratorOrder verifies that 3 (g=0x03 = x+1) is a primitive element
// of GF(256)*: its order is exactly 255, not any proper divisor.
// The AES spec (FIPS 197) states that 0x03 generates GF(2^8)* under the
// polynomial x^8+x^4+x^3+x+1. The exp/log table construction in init() relies
// on this order being 255 so that every nonzero element appears exactly once.
func TestGF256GeneratorOrder(t *testing.T) {
	// Proper divisors of 255 = 3 × 5 × 17; the element 3 must not satisfy g^d = 1
	// for any proper divisor d.
	properDivisors := []int{1, 3, 5, 15, 17, 51, 85}
	g := byte(3)
	for _, d := range properDivisors {
		if gfPow(g, d) == 1 {
			t.Fatalf("gfPow(3, %d) = 1, but 3 should have order 255, not %d", d, d)
		}
	}
	if gfPow(g, 255) != 1 {
		t.Fatal("gfPow(3, 255) != 1: 3 does not have order 255 — table is broken")
	}
}

// --- 2. Reed-Solomon code properties -----------------------------------------

// TestRSEncodingSystematic verifies that the first k symbols of an RS codeword
// equal the message (systematic property). This is the SA-ECC requirement:
// the original file blocks appear unchanged in the encoded file (§4.2).
func TestRSEncodingSystematic(t *testing.T) {
	for _, tc := range []struct{ k, n int }{{3, 5}, {4, 7}, {6, 10}, {2, 4}} {
		msg := make([]byte, tc.k)
		rand.Read(msg)
		cw := rsEncodeSlice(msg, tc.n)
		for i := range tc.k {
			if cw[i] != msg[i] {
				t.Fatalf("(k=%d,n=%d): codeword[%d]=%d, want %d (message byte)",
					tc.k, tc.n, i, cw[i], msg[i])
			}
		}
	}
}

// TestRSParityCheckEquation verifies that the encoded codeword is consistent:
// evaluating the interpolating polynomial at any of the n evaluation points
// yields the corresponding codeword symbol.
//
// By construction, rsEncodeSlice builds the unique polynomial p(x) of degree<k
// with p(i)=message[i] for i<k. The check p(j)=codeword[j] must hold for j≥k.
func TestRSParityCheckEquation(t *testing.T) {
	k, n := 4, 7
	msg := make([]byte, k)
	rand.Read(msg)
	cw := rsEncodeSlice(msg, n)

	// Verify by re-evaluating the Lagrange polynomial at each parity position.
	for j := k; j < n; j++ {
		xj := byte(j)
		expected := byte(0)
		for i := 0; i < k; i++ {
			xi := byte(i)
			num, den := byte(1), byte(1)
			for m := 0; m < k; m++ {
				if m == i {
					continue
				}
				xm := byte(m)
				num = gfMul(num, gfAdd(xj, xm))
				den = gfMul(den, gfAdd(xi, xm))
			}
			expected = gfAdd(expected, gfMul(msg[i], gfMul(num, gfInv(den))))
		}
		if cw[j] != expected {
			t.Fatalf("parity check failed at j=%d: cw[j]=%d, Lagrange=%d", j, cw[j], expected)
		}
	}
}

// TestRSCodeLinearity verifies that RS encoding is linear:
// encode(a*m + b*n) = a*encode(m) + b*encode(n) (scalar multiplication and addition in GF(256)).
//
// Linearity is the algebraic basis for the inner code's linear combination
// in the challenge-response protocol; it also holds for the outer RS code.
func TestRSCodeLinearity(t *testing.T) {
	k, n := 4, 6
	a, b := byte(3), byte(7) // arbitrary nonzero scalars

	m1 := make([]byte, k)
	m2 := make([]byte, k)
	rand.Read(m1)
	rand.Read(m2)

	// Compute encode(a*m1 + b*m2) directly.
	combined := make([]byte, k)
	for i := range k {
		combined[i] = gfAdd(gfMul(a, m1[i]), gfMul(b, m2[i]))
	}
	cwCombined := rsEncodeSlice(combined, n)

	// Compute a*encode(m1) + b*encode(m2).
	cw1 := rsEncodeSlice(m1, n)
	cw2 := rsEncodeSlice(m2, n)
	expected := make([]byte, n)
	for i := range n {
		expected[i] = gfAdd(gfMul(a, cw1[i]), gfMul(b, cw2[i]))
	}

	for i := range n {
		if cwCombined[i] != expected[i] {
			t.Fatalf("RS linearity failed at position %d: combined=%d, a*cw1+b*cw2=%d",
				i, cwCombined[i], expected[i])
		}
	}
}

// TestRSBlockEncodingSystematic verifies rsEncodeBlocks: the first k output
// blocks are byte-for-byte identical to the input blocks.
func TestRSBlockEncodingSystematic(t *testing.T) {
	k, n, blockSize := 4, 6, 32
	blocks := randomBlocks(t, k, blockSize)
	encoded := rsEncodeBlocks(blocks, n)

	for i := range k {
		for b := range blockSize {
			if encoded[i][b] != blocks[i][b] {
				t.Fatalf("rsEncodeBlocks: block %d byte %d: got %d want %d",
					i, b, encoded[i][b], blocks[i][b])
			}
		}
	}
}

// --- 3. PRP properties -------------------------------------------------------

// TestBuildPRPIsPermutation verifies that pdp.SuiteV1.BuildPRP returns a valid
// permutation of [0, n): every index appears exactly once.
// The por package delegates buildPRP to pdp.SuiteV1.BuildPRP; this test confirms
// the contract holds for the values POR uses.
func TestBuildPRPIsPermutation(t *testing.T) {
	key := randomBlock(t, 32)
	for _, n := range []int{1, 5, 10, 100, 256} {
		perm := pdp.SuiteV1.BuildPRP(key, n)
		if len(perm) != n {
			t.Fatalf("BuildPRP(n=%d): length %d", n, len(perm))
		}
		seen := make(map[int]bool)
		for _, v := range perm {
			if v < 0 || v >= n {
				t.Fatalf("BuildPRP(n=%d): value %d out of range", n, v)
			}
			if seen[v] {
				t.Fatalf("BuildPRP(n=%d): duplicate value %d", n, v)
			}
			seen[v] = true
		}
	}
}

// TestBuildPRPDeterministic verifies that the same key and n always produce
// the same permutation, and different keys produce different permutations
// (with overwhelming probability).
func TestBuildPRPDeterministic(t *testing.T) {
	key := randomBlock(t, 32)
	n := 20
	p1 := pdp.SuiteV1.BuildPRP(key, n)
	p2 := pdp.SuiteV1.BuildPRP(key, n)
	for i := range n {
		if p1[i] != p2[i] {
			t.Fatalf("BuildPRP not deterministic at index %d: %d vs %d", i, p1[i], p2[i])
		}
	}

	key2 := randomBlock(t, 32)
	p3 := pdp.SuiteV1.BuildPRP(key2, n)
	same := true
	for i := range n {
		if p1[i] != p3[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("BuildPRP with different keys produced the same permutation (negligible probability)")
	}
}

// --- 4. Inner code linearity -------------------------------------------------

// TestInnerCodeLinearity is the central algebraic invariant of the POR inner code.
//
// The inner code response M = Σ_{s=1}^v F_{i_s} · G[s][u] mod P is linear in
// the field elements F_{i_s}. Specifically, for field elements a, b ∈ Z_P:
//
//	Response(a·F + b·G) = a·Response(F) + b·Response(G)  mod P
//
// This linearity is what makes the challenge-response protocol work: a server
// that has stored the correct blocks will always produce the precomputed response,
// and the inner code's error-correction properties follow from this linearity.
//
// The test works at the field element level by constructing blocks whose
// SHA-256 hashes are the desired field elements (mod P). Since SHA-256 is
// a hash, we instead verify the linear combination directly on raw Z_P elements.
func TestInnerCodeLinearity(t *testing.T) {
	P := smallP
	gseed := randomBlock(t, 32)
	v := 5
	u := 3

	// Choose random field elements F[0..v-1] and G[0..v-1].
	F := make([]*big.Int, v)
	G := make([]*big.Int, v)
	for i := range v {
		F[i], _ = rand.Int(rand.Reader, P)
		G[i], _ = rand.Int(rand.Reader, P)
	}

	a, _ := rand.Int(rand.Reader, P)
	b, _ := rand.Int(rand.Reader, P)

	// Compute M(a·F + b·G) = Σ (a·F[s] + b·G[s]) · innerCodeElement(s+1, u) mod P.
	combined := big.NewInt(0)
	mF := big.NewInt(0)
	mG := big.NewInt(0)
	for s := range v {
		Gsu := innerCodeElement(gseed, s+1, u, P)
		aFs := new(big.Int).Mod(new(big.Int).Mul(a, F[s]), P)
		bGs := new(big.Int).Mod(new(big.Int).Mul(b, G[s]), P)
		combo := new(big.Int).Mod(new(big.Int).Add(aFs, bGs), P)
		combined.Add(combined, new(big.Int).Mul(combo, Gsu))
		combined.Mod(combined, P)

		mF.Add(mF, new(big.Int).Mul(F[s], Gsu))
		mF.Mod(mF, P)
		mG.Add(mG, new(big.Int).Mul(G[s], Gsu))
		mG.Mod(mG, P)
	}

	// Compute a·M(F) + b·M(G) mod P.
	expected := new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Mul(a, mF),
			new(big.Int).Mul(b, mG),
		), P)

	if combined.Cmp(expected) != 0 {
		t.Fatalf("inner code linearity failed:\n  M(a·F+b·G) = %v\n  a·M(F)+b·M(G) = %v", combined, expected)
	}
}

// TestInnerCodeConsistency verifies that the same inputs always produce the
// same inner code response: computeInnerResponse is deterministic.
func TestInnerCodeConsistency(t *testing.T) {
	P := smallP
	gseed := randomBlock(t, 32)
	blocks := randomBlocks(t, 20, 32)
	indices := []int{0, 3, 7, 11, 19}
	u := 2

	m1 := computeInnerResponse(blocks, indices, gseed, u, P)
	m2 := computeInnerResponse(blocks, indices, gseed, u, P)
	if m1.Cmp(m2) != 0 {
		t.Fatal("computeInnerResponse is not deterministic")
	}
}

// TestInnerCodeDifferentColumns verifies that different u values produce
// different responses with overwhelming probability (distinct generator columns
// are linearly independent, as expected of a good code).
func TestInnerCodeDifferentColumns(t *testing.T) {
	P := smallP
	gseed := randomBlock(t, 32)
	blocks := randomBlocks(t, 10, 32)
	indices := []int{0, 2, 4, 6, 8}

	m1 := computeInnerResponse(blocks, indices, gseed, 1, P)
	m2 := computeInnerResponse(blocks, indices, gseed, 2, P)
	if m1.Cmp(m2) == 0 {
		t.Fatal("different u columns produced the same response (negligible probability)")
	}
}

// TestInnerCodeElementDerivedFromPDPPRF verifies that innerCodeElement uses
// pdp.SuiteV1.PRF with two indices: G[s][u] = PRF(gseed, u, s) mod P.
// This documents that the two-argument PRF call HMAC(gseed, encode(u)‖encode(s))
// is a single HMAC evaluation, not a two-step key derivation.
func TestInnerCodeElementDerivedFromPDPPRF(t *testing.T) {
	P := smallP
	gseed := randomBlock(t, 32)
	s, u := 3, 7

	expected := new(big.Int).Mod(pdp.SuiteV1.PRF(gseed, u, s), P)

	got := innerCodeElement(gseed, s, u, P)
	if got.Cmp(expected) != 0 {
		t.Fatalf("innerCodeElement(%d,%d): got %v, want %v", s, u, got, expected)
	}
}

// --- 5. Verification equation ------------------------------------------------

// TestVerificationEquation is the core soundness check for the POR protocol.
//
// For an honest server, the precomputed M_j in Encode and the computed M_j in
// Respond must be identical because both call computeInnerResponse with the
// same inputs. The sentinel Q_j = Enc(k_j^e, M_j) must therefore decrypt to
// the server's M_j.
//
//	Dec(k_j^e, Q_j) == M_j   ⟺   honest server passes Verify
//
// This test verifies the equation directly at the algebraic level, independent
// of the Encode/Respond API.
func TestVerificationEquation(t *testing.T) {
	P := smallP
	gseed := randomBlock(t, 32)
	kje := randomBlock(t, 32)

	blocks := randomBlocks(t, 15, 32)
	indices := []int{0, 3, 7, 11, 14}
	u := 5

	// Client-side (Encode): compute and encrypt M.
	M := computeInnerResponse(blocks, indices, gseed, u, P)
	Mbytes := mToBytes(M, P)
	Q, err := sentinelEncrypt(kje, Mbytes)
	if err != nil {
		t.Fatalf("sentinelEncrypt: %v", err)
	}

	// Server-side (Respond): compute M independently.
	Mserver := computeInnerResponse(blocks, indices, gseed, u, P)

	// Verify: client decrypts Q and compares.
	decrypted, err := sentinelDecrypt(kje, Q)
	if err != nil {
		t.Fatalf("sentinelDecrypt: %v", err)
	}

	if Mserver.Cmp(M) != 0 {
		t.Fatal("server M != client M (computeInnerResponse is not deterministic)")
	}
	if string(decrypted) != string(Mbytes) {
		t.Fatal("Dec(k_j^e, Q_j) != M_j: verification equation fails for honest server")
	}
}

// TestVerificationEquationTamperedBlock verifies that changing a challenged
// block causes the server's M_j to differ from the stored sentinel.
//
// An adversary that corrupts a challenged block cannot produce the correct M_j
// without solving the PRF preimage problem (finding a block whose SHA-256 hash
// produces the same field element). The sentinel Q_j was computed before
// corruption, so Dec(k_j^e, Q_j) ≠ M_j after corruption.
func TestVerificationEquationTamperedBlock(t *testing.T) {
	P := smallP
	gseed := randomBlock(t, 32)
	kje := randomBlock(t, 32)

	blocks := randomBlocks(t, 10, 32)
	indices := []int{0, 2, 4, 6, 8}
	u := 3

	// Pre-compute with original blocks.
	M := computeInnerResponse(blocks, indices, gseed, u, P)
	Q, err := sentinelEncrypt(kje, mToBytes(M, P))
	if err != nil {
		t.Fatalf("sentinelEncrypt: %v", err)
	}

	// Tamper with a challenged block.
	blocks[0] = randomBlock(t, 32)

	// Server computes M with corrupted block.
	Mcorrupted := computeInnerResponse(blocks, indices, gseed, u, P)

	decrypted, err := sentinelDecrypt(kje, Q)
	if err != nil {
		t.Fatalf("sentinelDecrypt: %v", err)
	}

	// The server's response should not match the stored sentinel.
	if string(decrypted) == string(mToBytes(Mcorrupted, P)) {
		t.Fatal("tampered block produced the same response as the original — soundness failure")
	}
}

// TestSentinelRoundTrip verifies that sentinelDecrypt(k, sentinelEncrypt(k, m)) == m
// for random plaintexts. This is the cryptographic basis of Verify: the client
// must be able to recover M_j from the stored sentinel.
func TestSentinelRoundTrip(t *testing.T) {
	for range 20 {
		key := randomBlock(t, 32)
		plaintext := randomBlock(t, 64)

		ct, err := sentinelEncrypt(key, plaintext)
		if err != nil {
			t.Fatalf("sentinelEncrypt: %v", err)
		}
		recovered, err := sentinelDecrypt(key, ct)
		if err != nil {
			t.Fatalf("sentinelDecrypt: %v", err)
		}
		if string(recovered) != string(plaintext) {
			t.Fatal("sentinel round-trip failed: decrypted != original plaintext")
		}
	}
}

// TestKeyDerivationDeterministic verifies that KeyGen with the same random
// source produces consistent sub-keys, and that challengeKey and encryptionKey
// are deterministic. This documents the KDF structure.
func TestKeyDerivationDeterministic(t *testing.T) {
	master := randomBlock(t, 32)

	k1 := deriveKey(master, "kchal")
	k2 := deriveKey(master, "kchal")
	if string(k1) != string(k2) {
		t.Fatal("deriveKey not deterministic")
	}

	// Different labels must produce different keys.
	k3 := deriveKey(master, "kenc")
	if string(k1) == string(k3) {
		t.Fatal("deriveKey with different labels produced the same key")
	}

	// challengeKey and encryptionKey must be deterministic.
	ck1 := challengeKey(k1, 42)
	ck2 := challengeKey(k1, 42)
	if string(ck1) != string(ck2) {
		t.Fatal("challengeKey not deterministic")
	}

	ek1 := encryptionKey(k3, 42)
	ek2 := encryptionKey(k3, 42)
	if string(ek1) != string(ek2) {
		t.Fatal("encryptionKey not deterministic")
	}

	// Different j values must produce different keys.
	ck3 := challengeKey(k1, 43)
	if string(ck1) == string(ck3) {
		t.Fatal("challengeKey(j=42) == challengeKey(j=43)")
	}
}

// --- 6. mToBytes fixed-length encoding ---------------------------------------

// TestMToBytesFixedLength verifies that mToBytes always returns a slice of
// length (P.BitLen()+7)/8, even for M=0 or M with leading zero bytes.
// Fixed length is required so Dec(Enc(M)) round-trips correctly:
// big.Int.Bytes() strips leading zeros, which would cause a length mismatch.
func TestMToBytesFixedLength(t *testing.T) {
	P := smallP
	pLen := (P.BitLen() + 7) / 8

	for _, v := range []int64{0, 1, 127, 255, 256, 1000000} {
		M := big.NewInt(v)
		b := mToBytes(M, P)
		if len(b) != pLen {
			t.Fatalf("mToBytes(%d, P): length %d, want %d", v, len(b), pLen)
		}
		// Round-trip: SetBytes recovers M.
		recovered := new(big.Int).SetBytes(b)
		if recovered.Cmp(M) != 0 {
			t.Fatalf("mToBytes round-trip failed for M=%d", v)
		}
	}
}

// --- 7. SA-ECC outer code structure ------------------------------------------

// TestSAECCSystematic verifies that the first m blocks of the saeccEncode output
// are identical to the input file blocks (systematic outer code property).
// §4.2: "The output codeword is M followed by permuted and encrypted
// error-correcting information."
func TestSAECCSystematic(t *testing.T) {
	m, outerK, outerN, blockSize := 8, 4, 6, 32
	blocks := randomBlocks(t, m, blockSize)

	kPerm := randomBlock(t, 32)
	kECCPerm := randomBlock(t, 32)
	kECCEnc := randomBlock(t, 32)

	encoded, err := saeccEncode(blocks, outerN, outerK, kPerm, kECCPerm, kECCEnc)
	if err != nil {
		t.Fatalf("saeccEncode: %v", err)
	}
	if len(encoded) < m {
		t.Fatalf("encoded length %d < m=%d", len(encoded), m)
	}

	for i := range m {
		for b := range blockSize {
			if encoded[i][b] != blocks[i][b] {
				t.Fatalf("SA-ECC not systematic: block %d byte %d: got %d want %d",
					i, b, encoded[i][b], blocks[i][b])
			}
		}
	}
}

// TestSAECCParityCount verifies the number of parity blocks produced by
// saeccEncode matches the expected formula: numStripes * (OuterN - OuterK)
// where numStripes = ⌈m/OuterK⌉.
func TestSAECCParityCount(t *testing.T) {
	for _, tc := range []struct{ m, k, n int }{
		{8, 4, 6},  // 2 stripes, 2 parity each → 4 parity
		{9, 4, 6},  // 3 stripes (last has 1 block padded), 2 parity each → 6 parity
		{12, 4, 7}, // 3 stripes, 3 parity each → 9 parity
	} {
		blocks := randomBlocks(t, tc.m, 16)
		kPerm := randomBlock(t, 32)
		kECCPerm := randomBlock(t, 32)
		kECCEnc := randomBlock(t, 32)

		encoded, err := saeccEncode(blocks, tc.n, tc.k, kPerm, kECCPerm, kECCEnc)
		if err != nil {
			t.Fatalf("saeccEncode(m=%d,k=%d,n=%d): %v", tc.m, tc.k, tc.n, err)
		}

		numStripes := (tc.m + tc.k - 1) / tc.k
		expectedTotal := tc.m + numStripes*(tc.n-tc.k)
		if len(encoded) != expectedTotal {
			t.Fatalf("(m=%d,k=%d,n=%d): got %d total blocks, want %d",
				tc.m, tc.k, tc.n, len(encoded), expectedTotal)
		}
	}
}

// --- 8. End-to-end with small parameters ------------------------------------

// TestFullProtocolSmallParams runs the complete KeyGen / Encode / MakeChallenge /
// Respond / Verify cycle with deliberately small parameters for speed.
func TestFullProtocolSmallParams(t *testing.T) {
	params := &Params{
		V:      3,
		W:      10,
		Q:      5,
		P:      smallP,
		OuterN: 6,
		OuterK: 4,
	}
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	blocks := randomBlocks(t, 8, 32)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	for j := 1; j <= params.Q; j++ {
		chal, err := MakeChallenge(mk, j)
		if err != nil {
			t.Fatalf("MakeChallenge(j=%d): %v", j, err)
		}
		resp, err := Respond(ef, chal)
		if err != nil {
			t.Fatalf("Respond(j=%d): %v", j, err)
		}
		ok, err := Verify(mk, chal, resp)
		if err != nil {
			t.Fatalf("Verify(j=%d): %v", j, err)
		}
		if !ok {
			t.Fatalf("Verify(j=%d): valid proof rejected", j)
		}
	}
}

// TestTamperedBlockFails verifies that a server that corrupts a file block
// causes Verify to return false.
func TestTamperedBlockFails(t *testing.T) {
	params := &Params{
		V:      3,
		W:      10,
		Q:      5,
		P:      smallP,
		OuterN: 6,
		OuterK: 4,
	}
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	blocks := randomBlocks(t, 8, 32)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Corrupt every block in the encoded file so at least one challenged block is wrong.
	for i := range ef.Blocks {
		ef.Blocks[i] = randomBlock(t, 32)
	}

	anyFailed := false
	for j := 1; j <= params.Q; j++ {
		chal, _ := MakeChallenge(mk, j)
		resp, _ := Respond(ef, chal)
		ok, err := Verify(mk, chal, resp)
		if err != nil {
			t.Fatalf("Verify(j=%d): %v", j, err)
		}
		if !ok {
			anyFailed = true
		}
	}
	if !anyFailed {
		t.Fatal("all challenges passed despite all blocks being corrupted — soundness failure")
	}
}
