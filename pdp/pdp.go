// Package pdp defines the PublicKey and Suite types shared by the Ateniese
// (static) and Erway (dynamic) PDP schemes, and provides the RSA group-setup
// primitives both schemes use for key generation.
//
// Callers who want to run a complete PDP protocol should import one of the
// sub-packages:
//
//	pdp/ateniese — S-PDP (Ateniese et al., CCS 2007), static, unlimited challenges
//	pdp/erway    — DPDP I (Erway et al., CCS 2009), dynamic (insert/modify/delete)
package pdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
)

// PublicKey holds the RSA group parameters shared by both PDP schemes.
//
//   - N is the RSA modulus N = p*q, where p and q are safe primes.
//   - G is a generator of QR_N, the cyclic group of quadratic residues mod N,
//     with order phi = p'*q' (where p = 2p'+1, q = 2q'+1).
type PublicKey struct {
	N *big.Int
	G *big.Int
}

// MakePublicKey generates a fresh RSA group over safe primes.
// k is the security parameter in bits for each prime; N is approximately 2k bits.
// Both the Ateniese and Erway schemes call this from their own KeyGen functions.
func MakePublicKey(k int) (*PublicKey, error) {
	p, _, err := GenerateSafePrime(k)
	if err != nil {
		return nil, fmt.Errorf("pdp.MakePublicKey: p: %w", err)
	}
	q, _, err := GenerateSafePrime(k)
	if err != nil {
		return nil, fmt.Errorf("pdp.MakePublicKey: q: %w", err)
	}
	N := new(big.Int).Mul(p, q)
	G, err := GenerateGQRN(N)
	if err != nil {
		return nil, fmt.Errorf("pdp.MakePublicKey: G: %w", err)
	}
	return &PublicKey{N: N, G: G}, nil
}

// GenerateSafePrime returns a safe prime p = 2*p' + 1 of the requested bit
// length, along with the Sophie Germain prime p'. Both sub-packages use this
// to build N.
func GenerateSafePrime(bits int) (p, pPrime *big.Int, err error) {
	one := big.NewInt(1)
	for {
		pPrime, err = rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, nil, err
		}
		p = new(big.Int).Lsh(pPrime, 1)
		p.Add(p, one)
		if p.ProbablyPrime(20) {
			return p, pPrime, nil
		}
	}
}

// GenerateGQRN returns a generator g of QR_N — the cyclic subgroup of quadratic
// residues mod N of order p'*q'. Per §4.3 of the Ateniese paper: choose
// a ← Z*_N with gcd(a±1, N) = 1, then set g = a² mod N.
func GenerateGQRN(N *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	nMinus1 := new(big.Int).Sub(N, one)
	for {
		a, err := rand.Int(rand.Reader, nMinus1)
		if err != nil {
			return nil, err
		}
		a.Add(a, one)
		if new(big.Int).GCD(nil, nil, a, N).Cmp(one) != 0 {
			continue
		}
		aMinus1 := new(big.Int).Sub(a, one)
		if new(big.Int).GCD(nil, nil, aMinus1, N).Cmp(one) != 0 {
			continue
		}
		aPlus1 := new(big.Int).Add(a, one)
		if new(big.Int).GCD(nil, nil, aPlus1, N).Cmp(one) != 0 {
			continue
		}
		return new(big.Int).Exp(a, two, N), nil
	}
}

// ─── Suite ────────────────────────────────────────────────────────────────────

// Suite bundles the cryptographic primitives that govern block selection and
// coefficient generation. These primitives are shared by the Ateniese S-PDP
// scheme, the Erway DPDP I scheme, and the BJ-POR construction — any scheme
// that needs a PRP for block selection or a PRF for coefficient derivation
// should reference a Suite rather than hard-coding a specific hash construction.
//
// The numeric ID is stored in every ateniese.Tag so that proof operations can
// confirm all tags share the same algorithm.
//
// HashToQRN is used by the Ateniese scheme's tag and verification operations;
// schemes that do not use RSA-based tags can ignore this field.
//
// Obtain a Suite via one of the package-level variables (SuiteV1, …) rather
// than constructing one directly.
type Suite struct {
	id uint8

	// HashBlock maps raw block bytes to a *big.Int exponent, used in both
	// tagging and proof accumulation. Schemes that use g^{H(block)} mod N
	// (Ateniese, Erway) call this to convert arbitrary-length block data to a
	// fixed-width integer; the deviation from paper notation is documented in
	// each scheme's package doc.
	HashBlock func(data []byte) *big.Int

	// HashToQRN maps an arbitrary byte string to a near-uniform element of
	// QR_N. Used by the Ateniese scheme in TagBlock and CheckProof.
	HashToQRN func(data []byte, N *big.Int) *big.Int

	// PRF is a keyed pseudorandom function. A single index call produces the
	// per-block coefficient a_j used in PDP. A two-index call PRF(key, u, s)
	// folds u into the HMAC input before s, providing domain separation for
	// multi-dimensional applications such as the BJ-POR inner-code matrix
	// G[s][u] = PRF(GSeed, u, s).
	PRF func(key []byte, js ...int) *big.Int

	// BuildPRP constructs a pseudorandom permutation of [0, n) from key.
	// Called with the same key and n by both GenProof and CheckProof.
	BuildPRP func(key []byte, n int) []int
}

// ID returns the suite's numeric version identifier, suitable for storage in
// serialized Tags and Proofs.
func (s *Suite) ID() uint8 { return s.id }

var suiteRegistry = map[uint8]*Suite{}

// SuiteByID returns the Suite registered under id, or (nil, false) if no suite
// with that ID is known. Used by servers to dispatch proof operations to the
// correct algorithm based on the SuiteID embedded in incoming tags.
func SuiteByID(id uint8) (*Suite, bool) {
	s, ok := suiteRegistry[id]
	return s, ok
}

func registerSuite(s *Suite) *Suite {
	if _, exists := suiteRegistry[s.id]; exists {
		panic(fmt.Sprintf("pdp: duplicate suite ID %d", s.id))
	}
	suiteRegistry[s.id] = s
	return s
}

// SuiteV1 is the initial algorithm suite:
//   - HashBlock:  SHA-256
//   - HashToQRN: MGF1 (RFC 8017 §B.2.1) with SHA-256, bias < 2^{-128}
//   - PRF:       HMAC-SHA256 truncated to 128 bits
//   - BuildPRP:  sort-by-HMAC-SHA256
var SuiteV1 = registerSuite(&Suite{
	id:        1,
	HashBlock: sha256HashBlock,
	HashToQRN: mgf1SHA256HashToQRN,
	PRF:       hmacSHA256PRF128,
	BuildPRP:  hmacSHA256PRP,
})

// sha256HashBlock maps raw block bytes to a *big.Int via SHA-256.
func sha256HashBlock(data []byte) *big.Int {
	h := sha256.Sum256(data)
	return new(big.Int).SetBytes(h[:])
}

// mgf1SHA256HashToQRN maps an arbitrary byte string deterministically and
// near-uniformly into QR_N using MGF1 (RFC 8017 §B.2.1) with SHA-256.
//
// Per footnote 3 of the Ateniese paper, h is constructed by squaring the output
// of a full-domain hash over [0, N-1]. Generating ⌈(N.BitLen()+128)/8⌉ bytes
// before reducing mod N bounds the statistical bias to < 2^{-128}.
func mgf1SHA256HashToQRN(data []byte, N *big.Int) *big.Int {
	targetBytes := (N.BitLen() + 128 + 7) / 8
	var buf []byte
	for counter := uint32(0); len(buf) < targetBytes; counter++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h := sha256.New()
		h.Write(data)
		h.Write(c[:])
		buf = append(buf, h.Sum(nil)...)
	}
	x := new(big.Int).SetBytes(buf[:targetBytes])
	x.Mod(x, N)
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return new(big.Int).Exp(x, big.NewInt(2), N)
}

// hmacSHA256PRF128 is a 128-bit pseudorandom function based on HMAC-SHA-256.
//
// A single argument PRF(key, j) encodes j as a big-endian uint64 and is the
// standard per-block coefficient form. Multiple arguments PRF(key, u, s) fold
// each into the MAC in order, providing domain separation without a second
// HMAC call (used by BJ-POR's inner-code matrix G[s][u] = PRF(GSeed, u, s)).
func hmacSHA256PRF128(key []byte, js ...int) *big.Int {
	buf := make([]byte, 8)
	mac := hmac.New(sha256.New, key)
	for _, j := range js {
		binary.BigEndian.PutUint64(buf, uint64(j))
		mac.Write(buf)
	}
	return new(big.Int).SetBytes(mac.Sum(nil)[:16]) // 128 bits
}

// hmacSHA256PRP constructs a pseudorandom permutation of [0, n) keyed by key.
// It assigns each index i an HMAC-SHA-256 score and sorts by score, producing
// a deterministic permutation that both client and server can reconstruct
// from the same challenge key K1 without communicating the indices directly.
func hmacSHA256PRP(key []byte, n int) []int {
	type entry struct {
		index int
		score []byte
	}
	entries := make([]entry, n)
	for i := range n {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(i))
		mac := hmac.New(sha256.New, key)
		mac.Write(buf)
		entries[i] = entry{index: i, score: mac.Sum(nil)}
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].score, entries[j].score) < 0
	})
	perm := make([]int, n)
	for i := range n {
		perm[i] = entries[i].index
	}
	return perm
}
