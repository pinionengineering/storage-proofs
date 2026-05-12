// Package pdp implements the Scalable Provable Data Possession (S-PDP) protocol
// from the paper "Provable Data Possession at Untrusted Stores" by Ateniese et al.
// A copy of the paper is in doc/provable-data-possession.pdf.
//
// # Overview
//
// S-PDP lets a client (C) verify that a remote server (S) is faithfully storing
// a file without downloading the file. The protocol has three phases:
//
//  1. Setup: C splits the file into n blocks, generates a key pair, computes a
//     cryptographic tag for each block, and uploads the blocks and tags to S. C
//     then deletes its local copies of the blocks and tags, keeping only (pk, sk).
//
//  2. Challenge: C generates a random challenge that names a subset of blocks (via
//     a pseudorandom permutation) and sends it to S. The challenge also includes a
//     public blinding factor Gs = g^s, where s is a random secret C keeps private.
//
//  3. Response & Verification: S calls GenProof to produce an aggregated proof V
//     and returns it to C. C calls CheckProof with s to verify V.
//
// # Versioning
//
// Every Tag embeds a Suite ID so the verifier always knows which algorithm was
// used to create it. Call TagBlock, GenProof, and CheckProof as methods on a
// Suite value:
//
//	tag, err   := pdp.SuiteV1.TagBlock(pk, sk, block, w) // w is the block identifier
//	proof, err := pdp.SuiteV1.GenProof(pk, blocks, chal, tags)
//	ok, err    := pdp.SuiteV1.CheckProof(pk, sk, s, tags, chal, proof)
//
// To introduce a new algorithm variant, define a new Suite with different
// function implementations and a new ID — existing tags remain verifiable
// against the suite that created them.
//
// # Deviations from the paper
//
// Block data is SHA-256 hashed before use as a group exponent (necessary for
// arbitrary-length blocks; applied identically in TagBlock and GenProof).
//
// SuiteV1 uses MGF1 (RFC 8017 §B.2.1) with SHA-256 for hashToQRN, producing a
// near-uniform full-domain hash over QR_N (paper footnote 3, bias < 2^{-128}).
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

// Suite bundles the cryptographic primitives that govern tag creation, proof
// generation, and verification. Its numeric ID is stored in every Tag so that
// GenProof and CheckProof can confirm all tags share the same algorithm.
//
// Each field is a function so that a new suite can substitute a completely
// different implementation without touching the protocol logic. Obtain a Suite
// via one of the package-level variables (SuiteV1, …) rather than constructing
// one directly.
type Suite struct {
	// id is the numeric version identifier stored in every Tag.
	id uint8

	// HashToQRN maps an arbitrary byte string to a near-uniform element of
	// QR_N. Must be deterministic. Called in TagBlock (with W_i) and in
	// CheckProof (with tag.W); never called by the server during GenProof.
	HashToQRN func(data []byte, N *big.Int) *big.Int

	// PRF is a keyed pseudorandom function. When called with a single index
	// it produces the per-block coefficient a_j used in PDP. When called with
	// two indices (seed, j) it folds the seed into the HMAC input, giving a
	// domain-separated output useful for multi-dimensional PRF applications
	// such as the POR inner-code generator matrix G[s][u] = PRF(GSeed, u, s).
	// The single-index call is identical to the original single-argument form,
	// so existing PDP tags and proofs are unaffected.
	PRF func(key []byte, js ...int) *big.Int

	// BuildPRP constructs a pseudorandom permutation of [0, n) from key.
	// Called with the same key and n by both GenProof and CheckProof.
	BuildPRP func(key []byte, n int) []int
}

// ID returns the suite's numeric version identifier, suitable for storage or
// wire encoding alongside serialized Tags and Proofs.
func (s *Suite) ID() uint8 { return s.id }

// suiteRegistry maps suite IDs to their Suite definitions. All package-level
// Suite variables are registered here at init time so that SuiteByID can
// resolve them without callers needing to maintain their own switch statements.
var suiteRegistry = map[uint8]*Suite{}

// SuiteByID returns the Suite registered under id, or (nil, false) if no
// suite with that ID is known. Servers use this to dispatch GenProof to the
// correct algorithm based on the SuiteID embedded in incoming Tags:
//
//	suite, ok := pdp.SuiteByID(tags[0].SuiteID)
//	if !ok {
//	    return fmt.Errorf("unknown suite %d", tags[0].SuiteID)
//	}
//	proof, err := suite.GenProof(pk, blocks, chal, tags)
func SuiteByID(id uint8) (*Suite, bool) {
	s, ok := suiteRegistry[id]
	return s, ok
}

// registerSuite adds s to the registry. Called in init() for each defined suite.
// Panics on duplicate IDs to catch accidental collisions at startup.
func registerSuite(s *Suite) *Suite {
	if _, exists := suiteRegistry[s.id]; exists {
		panic(fmt.Sprintf("pdp: duplicate suite ID %d", s.id))
	}
	suiteRegistry[s.id] = s
	return s
}

// SuiteV1 is the initial algorithm suite:
//   - HashToQRN: MGF1 (RFC 8017 §B.2.1) with SHA-256, bias < 2^{-128}
//   - PRF:       HMAC-SHA256 truncated to 128 bits
//   - BuildPRP:  sort-by-HMAC-SHA256
var SuiteV1 = registerSuite(&Suite{
	id:        1,
	HashToQRN: mgf1SHA256HashToQRN,
	PRF:       hmacSHA256PRF128,
	BuildPRP:  hmacSHA256PRP,
})

// PublicKey is the client's public key, shared with the server.
//
//   - N is the RSA modulus N = p*q, where p and q are safe primes.
//   - G is a generator of QR_N, the cyclic group of quadratic residues mod N,
//     which has order phi = p'*q' (where p = 2p'+1, q = 2q'+1).
type PublicKey struct {
	N *big.Int
	G *big.Int
}

// SecretKey is the client's private key. It must never be sent to the server.
//
//   - E and D satisfy E*D ≡ 1 (mod Phi); E is the RSA encryption exponent and
//     D is the decryption (tag-signing) exponent.
//   - V is a random secret used to derive per-block identifiers W_i = V || i.
//   - Phi = p'*q' is the order of QR_N, used for exponent reduction in CheckProof.
type SecretKey struct {
	E   *big.Int
	D   *big.Int
	V   []byte
	Phi *big.Int
}

// Tag is the verification metadata for a single file block, computed by TagBlock.
//
//   - SuiteID identifies the algorithm suite used to create the tag.
//   - T is the tag value: T = (h(W) * g^m)^d mod N.
//   - W is the block identifier W_i = V || i, kept alongside T so the verifier
//     can recompute h(W_i) during CheckProof without access to V.
type Tag struct {
	SuiteID uint8
	T       *big.Int
	W       []byte
}

// Challenge is generated by the client and sent to the server to initiate an audit.
//
//   - SuiteID identifies which algorithm suite must be used to process this
//     challenge. K1 and K2 are only meaningful relative to the suite's PRF and
//     PRP implementations; a different suite would produce different block
//     selections and coefficients from the same keys. GenProof and CheckProof
//     both verify that the challenge's SuiteID matches the suite they are called
//     on and the SuiteID embedded in the tags.
//   - C is the number of blocks to challenge (must satisfy 1 <= C <= len(blocks)).
//   - K1 is a random key for the pseudorandom permutation that selects block indices.
//   - K2 is a random key for the pseudorandom function that assigns per-block coefficients.
//   - Gs is the public blinding factor g^s, where s is a random secret kept by the client.
//     The server uses Gs to compute rho = H((g^s)^μ) without learning s. The client
//     passes s (not Gs) to CheckProof to verify the response.
type Challenge struct {
	SuiteID uint8
	C       int
	K1      []byte
	K2      []byte
	Gs      *big.Int // g^s: public blinding factor; the client keeps s secret
}

// Proof is the server's response to a Challenge, produced by GenProof.
//
//   - T is the aggregated tag product: T = ∏ tag_i^{a_j} mod N.
//   - Rho is the binding hash: rho = SHA-256((g^s)^μ mod N), where μ = Σ a_j*m_j.
type Proof struct {
	T   *big.Int
	Rho []byte
}

// ---------------------------------------------------------------------------
// Suite V1 primitive implementations
// ---------------------------------------------------------------------------

// mgf1SHA256HashToQRN maps an arbitrary byte string deterministically and
// near-uniformly into QR_N using MGF1 (RFC 8017 §B.2.1) with SHA-256.
//
// Per footnote 3 of the paper, h is constructed by squaring the output of a
// full-domain hash (FDH) over [0, N-1]. Generating ⌈(N.BitLen()+128)/8⌉ bytes
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
	// x ≡ 0 mod N occurs with probability ≤ 1/N (negligible). 0 is not in Z*_N
	// and its square is not a valid QR_N element, so substitute 1 (also in QR_N).
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return new(big.Int).Exp(x, big.NewInt(2), N)
}

// hmacSHA256PRF128 is a 128-bit pseudorandom function based on HMAC-SHA-256.
//
// The paper leaves the coefficient length ℓ as a protocol parameter; 128 bits
// is standard and bounds μ = Σ a_j·m_j to at most C×256 bits, limiting the
// cost of the server-side exponentiation Gs^μ mod N.
//
// Each integer in js is written as a big-endian uint64, concatenated in order,
// forming the HMAC input. A single argument PRF(key, j) is identical to the
// original single-index form. Multiple arguments PRF(key, u, s) fold u into
// the input before s, providing domain separation without a second HMAC call.
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

// ---------------------------------------------------------------------------
// Key generation (suite-independent)
// ---------------------------------------------------------------------------

// generateSafePrime returns a safe prime p = 2*p' + 1 of the requested bit
// length, along with the Sophie Germain prime p'. Safe primes ensure that QR_N
// has a known, prime-order subgroup structure: |QR_N| = p'*q'.
func generateSafePrime(bits int) (p, pPrime *big.Int, err error) {
	one := big.NewInt(1)
	for {
		pPrime, err = rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, nil, err
		}
		// p = 2*pPrime + 1
		p = new(big.Int).Lsh(pPrime, 1)
		p.Add(p, one)
		if p.ProbablyPrime(20) {
			return p, pPrime, nil
		}
	}
}

// generateGQRN returns a generator g of QR_N — the cyclic subgroup of quadratic
// residues mod N of order p'*q'.
//
// Per §4.3 of the paper: choose a ← Z*_N such that gcd(a±1, N) = 1, then set
// g = a² mod N. Squaring maps a into QR_N. The gcd conditions ensure a ≢ ±1 mod p
// and a ≢ ±1 mod q, which excludes the elements whose squares collapse to 1.
// The probability that a random a² lands in a proper subgroup of QR_N is at most
// (p' + q') / (p'q') ≈ 1/q' + 1/p', which is negligible for large primes.
func generateGQRN(N *big.Int) (G *big.Int, err error) {
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

// KeyGen generates a fresh key pair for the S-PDP scheme.
//
// k is the security parameter in bits; it controls the size of the safe primes
// used to build the RSA modulus (N is approximately 2k bits). The paper requires
// k ≥ 1024 for security; smaller values (e.g. k = 128) are only suitable for tests.
//
// Key generation is independent of the algorithm suite. The same key pair can
// be used with any Suite.
//
// The algorithm (§4.2 of the paper):
//  1. Generate safe primes p = 2p'+1 and q = 2q'+1; set N = p*q.
//  2. Set phi = p'*q', the order of QR_N.
//  3. Choose a random 256-bit prime e coprime to phi; compute d = e^{-1} mod phi.
//  4. Generate g, a generator of QR_N.
//  5. Draw a random secret v ∈ {0,1}^k, used to derive per-block identifiers.
func KeyGen(k int) (pk *PublicKey, sk *SecretKey, err error) {
	p, pPrime, err := generateSafePrime(k)
	if err != nil {
		return nil, nil, err
	}
	q, qPrime, err := generateSafePrime(k)
	if err != nil {
		return nil, nil, err
	}

	N := new(big.Int).Mul(p, q)

	// phi = p'*q' is the order of QR_N.
	// Note: the full Euler totient is phi(N) = (p-1)(q-1) = 4*p'*q', but the
	// relevant group order for elements of QR_N is p'*q'.
	phi := new(big.Int).Mul(pPrime, qPrime)

	// e is a 256-bit prime chosen coprime to phi.
	one := big.NewInt(1)
	var e *big.Int
	for {
		e, err = rand.Prime(rand.Reader, 256)
		if err != nil {
			return nil, nil, err
		}
		if new(big.Int).GCD(nil, nil, e, phi).Cmp(one) == 0 {
			break
		}
	}

	// d = e^{-1} mod phi; together e and d form the RSA trapdoor over QR_N.
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, nil, fmt.Errorf("mod inverse of e mod phi failed")
	}

	g, err := generateGQRN(N)
	if err != nil {
		return nil, nil, err
	}

	v := make([]byte, k/8)
	if _, err = rand.Read(v); err != nil {
		return nil, nil, err
	}

	pk = &PublicKey{N: N, G: g}
	sk = &SecretKey{E: e, D: d, V: v, Phi: phi}
	return pk, sk, nil
}

// ---------------------------------------------------------------------------
// Protocol operations (Suite methods)
// ---------------------------------------------------------------------------

// TagBlock computes the verification tag for block m with block identifier w.
//
// w is the full block identifier stored in the returned Tag.W field. The caller
// is responsible for constructing w — a typical choice is V || encode(index),
// which binds the tag to both the key pair (via V) and the block's position.
// Other schemes (e.g. V || CID bytes for a content-addressed DAG) are equally
// valid as long as w is unique within the key pair's scope.
//
// The algorithm (§4.2 of the paper):
//  1. Compute T = (h(w) * g^m)^d mod N.
//  2. Return (T, w) tagged with the suite ID.
//
// Deviation from the paper: m is SHA-256 hashed before being used as a group
// exponent, mapping arbitrary-length block data to a fixed 256-bit integer.
// GenProof applies the same hash, so the verification equation is unaffected.
//
// The tags (but not sk.V) are sent to the server along with the blocks.
func (s *Suite) TagBlock(pk *PublicKey, sk *SecretKey, m []byte, w []byte) (*Tag, error) {
	// mInt = SHA-256(m) interpreted as a big.Int exponent.
	hm := sha256.Sum256(m)
	mInt := new(big.Int).SetBytes(hm[:])

	h := s.HashToQRN(w, pk.N)                // h(w) ∈ QR_N
	gm := new(big.Int).Exp(pk.G, mInt, pk.N) // g^m mod N
	T := new(big.Int).Mul(gm, h)             // h(w) * g^m
	T.Mod(T, pk.N)
	T.Exp(T, sk.D, pk.N) // (h(w) * g^m)^d mod N

	return &Tag{SuiteID: s.id, T: T, W: w}, nil
}

// GenProof is run by the server to produce a proof of possession for the challenged blocks.
//
// All tags must carry the same SuiteID as the receiver; GenProof returns an
// error on any mismatch so the server never silently uses the wrong algorithm.
//
// The algorithm (§4.2 of the paper):
//  1. Use BuildPRP(K1, n) to select C block indices i_1 … i_C.
//  2. Use PRF(K2, j) to derive coefficient a_j for each selected block.
//  3. Compute the aggregated tag T = ∏ tag_{i_j}^{a_j} mod N.
//  4. Compute μ = Σ a_j * SHA-256(block_{i_j}) as an integer.
//  5. Compute rho = SHA-256((g^s)^μ mod N), where g^s = chal.Gs.
//
// blocks and tags must be the same length and chal.C must be in [1, len(blocks)].
func (s *Suite) GenProof(pk *PublicKey, blocks [][]byte, chal *Challenge, tags []*Tag) (*Proof, error) {
	if chal.SuiteID != s.id {
		return nil, fmt.Errorf("challenge suite %d does not match suite %d", chal.SuiteID, s.id)
	}
	if len(blocks) != len(tags) {
		return nil, fmt.Errorf("blocks and tags length mismatch: %d vs %d", len(blocks), len(tags))
	}
	if chal.C < 1 || chal.C > len(blocks) {
		return nil, fmt.Errorf("challenge C=%d out of range [1, %d]", chal.C, len(blocks))
	}

	perm := s.BuildPRP(chal.K1, len(blocks))

	T := big.NewInt(1)
	mu := big.NewInt(0)

	for j := 1; j <= chal.C; j++ {
		ij := perm[j-1] // convert 1-based challenge index to 0-based block index
		tag := tags[ij]

		if tag.SuiteID != s.id {
			return nil, fmt.Errorf("tag[%d] suite %d does not match suite %d", ij, tag.SuiteID, s.id)
		}

		aj := s.PRF(chal.K2, j)

		// Accumulate tag product: T = ∏ tag_i^{a_j} mod N
		term := new(big.Int).Exp(tag.T, aj, pk.N)
		T.Mul(T, term)
		T.Mod(T, pk.N)

		// Accumulate μ = Σ a_j * m_j  (m_j is the SHA-256 hash of the block,
		// matching the encoding used in TagBlock)
		hm := sha256.Sum256(blocks[ij])
		mInt := new(big.Int).SetBytes(hm[:])
		mu.Add(mu, new(big.Int).Mul(aj, mInt))
	}

	// rho = SHA-256((g^s)^μ mod N).  chal.Gs is g^s, the public blinding factor;
	// the server never learns s itself.
	gsmu := new(big.Int).Exp(chal.Gs, mu, pk.N)
	rho := sha256.Sum256(gsmu.Bytes())

	return &Proof{T: T, Rho: rho[:]}, nil
}

// CheckProof is run by the client to verify a proof returned by the server.
//
// secret is the client's per-challenge secret s (not transmitted to the server).
// chal.Gs must equal pk.G^secret mod N.
//
// All tags must carry the same SuiteID as the receiver; CheckProof returns an
// error on any mismatch.
//
// The verification equation (§4.2 of the paper):
//  1. Recompute H_prod = ∏ h(W_{i_j})^{a_j} mod N from the stored tags.
//  2. Recover g^μ = T^e / H_prod mod N.
//     This works because T^e = ∏(h(W_i)*g^m)^{d*e*a_j} = ∏ h(W_i)^{a_j} * g^{a_j*m_j}
//     = H_prod * g^μ, using d*e ≡ 1 mod p'q' (the order of QR_N).
//  3. Compute g^{sμ} = (g^μ)^s mod N and compare SHA-256(g^{sμ}) to proof.Rho.
func (s *Suite) CheckProof(pk *PublicKey, sk *SecretKey, secret *big.Int, tags []*Tag, chal *Challenge, proof *Proof) (bool, error) {
	if chal.SuiteID != s.id {
		return false, fmt.Errorf("challenge suite %d does not match suite %d", chal.SuiteID, s.id)
	}
	if chal.C < 1 || chal.C > len(tags) {
		return false, fmt.Errorf("challenge C=%d out of range [1, %d]", chal.C, len(tags))
	}

	perm := s.BuildPRP(chal.K1, len(tags))

	// H_prod = ∏ h(W_{i_j})^{a_j} mod N
	Hprod := big.NewInt(1)
	for j := 1; j <= chal.C; j++ {
		ij := perm[j-1]
		tag := tags[ij]

		if tag.SuiteID != s.id {
			return false, fmt.Errorf("tag[%d] suite %d does not match suite %d", ij, tag.SuiteID, s.id)
		}

		aj := s.PRF(chal.K2, j)
		// By Lagrange's theorem, every element of QR_N has order dividing
		// p'q' = sk.Phi, so x^k ≡ x^(k mod p'q') (mod N) for all x ∈ QR_N.
		// Reducing a_j mod phi shrinks the exponent without changing the group
		// element, and does not affect the verification equation.
		aj.Mod(aj, sk.Phi)

		h := s.HashToQRN(tag.W, pk.N)
		term := new(big.Int).Exp(h, aj, pk.N)
		Hprod.Mul(Hprod, term)
		Hprod.Mod(Hprod, pk.N)
	}

	// Recover g^μ = T^e * H_prod^{-1} mod N
	Te := new(big.Int).Exp(proof.T, sk.E, pk.N)
	Hinv := new(big.Int).ModInverse(Hprod, pk.N)
	if Hinv == nil {
		return false, fmt.Errorf("H_prod has no inverse mod N")
	}
	gmu := new(big.Int).Mul(Te, Hinv)
	gmu.Mod(gmu, pk.N)

	// Compute g^{sμ} = (g^μ)^s and compare to the server's rho
	gsmu := new(big.Int).Exp(gmu, secret, pk.N)
	expected := sha256.Sum256(gsmu.Bytes())

	return bytes.Equal(expected[:], proof.Rho), nil
}
