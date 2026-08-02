// Package ateniese implements the Scalable Provable Data Possession (S-PDP)
// protocol from "Provable Data Possession at Untrusted Stores" by Ateniese et al.
// (ACM CCS 2007). A copy of the paper is in doc/provable-data-possession.pdf.
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
// used to create it. Pass a *pdp.Suite to TagBlock, GenProof, and CheckProof:
//
//	tag, err   := ateniese.TagBlock(pdp.SuiteV1, pk, sk, block, id)
//	proof, err := ateniese.GenProof(pdp.SuiteV1, pk, blocks, chal, tags)
//	ok, err    := ateniese.CheckProof(pdp.SuiteV1, pk, sk, s, ids, chal, proof)
//
// To introduce a new algorithm variant, define a new pdp.Suite with different
// function implementations and a new ID; existing tags remain verifiable
// against the suite that created them.
//
// # Block identifiers
//
// The paper's own model names a block by its sequential position i in a
// single file, folding i directly into W_i = v||i (§4.3 preamble, Fig. 2
// TagBlock). This implementation generalizes i to id, an arbitrary
// caller-chosen byte string, so a single key pair can tag blocks addressed by
// identifier rather than position, for example the identifiers a
// blocks.BlockStore already assigns its own content. §4.3 discusses the
// sequential-index case for multiple files (prefixing i with a file ID, or
// drawing i from a single global counter); an arbitrary id subsumes both.
//
// BlockW computes W = v||id, and both TagBlock and CheckProof call BlockW
// rather than accepting W directly, so the two sides always agree on how an
// identifier maps to a group element. CheckProof takes ids, the verifier's
// own trusted, positional record of which identifier belongs at each
// position (e.g. a block store's IDs() at audit time, mirroring the
// convention por/sw.Verify uses for the same purpose). This matches the
// paper's own CheckProof(pk,sk,chal,V) (Definition 4.1), which takes no
// external tag or identifier input at all and instead recomputes W_ij = v||ij
// itself from sk and the challenge. A tag store that could hand CheckProof
// its own claimed W for a challenged position would let it substitute any
// other valid tag it holds for that position undetected; self-deriving W
// from the verifier's own ids removes that avenue entirely.
//
// # Deviations from the paper
//
// pdp.SuiteV1 uses MGF1 (RFC 8017 §B.2.1) with SHA-256 for HashToQRN, producing
// a near-uniform full-domain hash over QR_N (paper footnote 3, bias < 2^{-128}).
//
// Block data m is used directly as the group exponent, matching the paper.
// Callers should size blocks so exponentiation cost stays reasonable (the
// paper's experiments use blocks around |N| bits); there is no correctness
// requirement that m < N.
//
// # Scheme variant
//
// This package implements S-PDP (§4.3 / Fig. 2), the variant with random
// per-block coefficients a_j drawn from a PRF keyed with k2. Because the
// coefficients are distinct and unpredictable, the server must possess each
// individually challenged block to produce a valid proof, the strong data
// possession guarantee. The paper also describes E-PDP (§4.3, "A more efficient
// scheme, with weaker guarantees"), where all a_j = 1, reducing server work to
// a single modular exponentiation but proving only possession of the sum of the
// challenged blocks. E-PDP is not implemented here.
//
// # Parameter choices
//
// The paper requires e to be a large secret prime with e > λ (§4.3 preamble).
// This implementation uses a 256-bit random prime for e, corresponding to
// λ = 256. The RSA modulus is approximately 2k bits for the k passed to KeyGen;
// the paper recommends k ≥ 1024 in production.
//
// # Lagrange's theorem
//
// For any x in QR_N and integer k, x^k ≡ x^(k mod p'q') mod N, because QR_N
// is a cyclic group of order p'q' (Lagrange's theorem). CheckProof exploits
// this by reducing a_j mod phi = p'q' before computing h(W)^{a_j}, avoiding
// large-integer exponentiation without changing the group element. GenProof
// does not explicitly reduce a_j before computing tag^{a_j}; the result is
// identical because the same theorem applies. See TestExponentReductionModGroupOrder
// and TestMuReductionEquivalence in math_test.go for proof by example.
package ateniese

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

// SecretKey is the client's private key. It must never be sent to the server.
//
//   - E and D satisfy E*D ≡ 1 (mod Phi); E is the RSA encryption exponent and
//     D is the decryption (tag-signing) exponent.
//   - V is a random secret used to derive per-block identifiers W_i = V || id.
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
//
// Tag does not carry W. CheckProof recomputes W_i = V||id itself from the
// verifier's own secret key and its own trusted identifier list, matching the
// paper's CheckProof(pk,sk,chal,V) (Definition 4.1). See "Block identifiers"
// in the package doc for why W is never taken as external input.
type Tag struct {
	SuiteID uint8
	T       *big.Int
}

// Challenge is generated by the client and sent to the server to initiate an audit.
//
//   - SuiteID identifies which algorithm suite must be used to process this
//     challenge. K1 and K2 are only meaningful relative to the suite's PRF and
//     PRP implementations; a different suite would produce different block
//     selections and coefficients from the same keys. GenProof and CheckProof
//     both verify that the challenge's SuiteID matches the suite they are called
//     with and the SuiteID embedded in the tags.
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
// Key generation
// ---------------------------------------------------------------------------

// KeyGen generates a fresh key pair for the S-PDP scheme.
//
// k is the security parameter in bits; it controls the size of the safe primes
// used to build the RSA modulus (N is approximately 2k bits). The paper requires
// k ≥ 1024 for security; smaller values (e.g. k = 128) are only suitable for tests.
//
// Key generation is independent of the algorithm suite. The same key pair can
// be used with any pdp.Suite.
//
// The algorithm (§4.3 / Fig. 2, KeyGen):
//  1. Generate safe primes p = 2p'+1 and q = 2q'+1; set N = p*q. (§4.3 preamble)
//  2. Set phi = p'*q', the order of QR_N. (§4.3 preamble)
//  3. Choose a random 256-bit prime e coprime to phi; compute d = e^{-1} mod phi.
//     The paper requires both e > λ and d > λ (§4.3 preamble); λ = 256 here.
//     e is drawn as a 256-bit prime directly, so e > λ holds by construction.
//     d is not drawn independently; it falls out of e via modular inverse, so
//     d > λ is not enforced directly. It holds with overwhelming probability
//     since phi is many hundreds of bits larger than λ = 256 and d is
//     effectively uniform over [1, phi), not adversarially chosen.
//  4. Generate g, a generator of QR_N. (§4.3 preamble)
//  5. Draw a random secret v ∈ {0,1}^k, used to derive per-block identifiers.
func KeyGen(k int) (pk *pdp.PublicKey, sk *SecretKey, err error) {
	p, pPrime, err := pdp.GenerateSafePrime(k)
	if err != nil {
		return nil, nil, err
	}
	q, qPrime, err := pdp.GenerateSafePrime(k)
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

	g, err := pdp.GenerateGQRN(N)
	if err != nil {
		return nil, nil, err
	}

	v := make([]byte, k/8)
	if _, err = rand.Read(v); err != nil {
		return nil, nil, err
	}

	pk = &pdp.PublicKey{N: N, G: g}
	sk = &SecretKey{E: e, D: d, V: v, Phi: phi}
	return pk, sk, nil
}

// MarshalJSON implements json.Marshaler. Encodes E, D, V, Phi as big-endian bytes.
// Reference: §4.3 Ateniese et al., CCS 2007 (KeyGen output: e, d, v, phi).
func (sk SecretKey) MarshalJSON() ([]byte, error) {
	type wire struct {
		E   []byte `json:"e"`
		D   []byte `json:"d"`
		V   []byte `json:"v"`
		Phi []byte `json:"phi"`
	}
	return json.Marshal(wire{E: sk.E.Bytes(), D: sk.D.Bytes(), V: sk.V, Phi: sk.Phi.Bytes()})
}

// UnmarshalJSON implements json.Unmarshaler.
func (sk *SecretKey) UnmarshalJSON(data []byte) error {
	type wire struct {
		E   []byte `json:"e"`
		D   []byte `json:"d"`
		V   []byte `json:"v"`
		Phi []byte `json:"phi"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("ateniese.SecretKey: %w", err)
	}
	sk.E = new(big.Int).SetBytes(w.E)
	sk.D = new(big.Int).SetBytes(w.D)
	sk.V = w.V
	sk.Phi = new(big.Int).SetBytes(w.Phi)
	return nil
}

// ---------------------------------------------------------------------------
// Protocol operations
// ---------------------------------------------------------------------------

// BlockW computes the block identifier W = V||id (§4.3 Fig. 2 TagBlock step 1,
// generalized from the paper's sequential index i to an arbitrary,
// caller-chosen id; see "Block identifiers" in the package doc). TagBlock and
// CheckProof both call BlockW so the two sides always agree on the mapping
// from (V, id) to W without either one needing W passed in directly.
func BlockW(v, id []byte) []byte {
	return append(append([]byte(nil), v...), id...)
}

// TagBlock computes the verification tag for block m at identifier id.
//
// id is a caller-chosen identifier, unique within the key pair's scope. A
// typical choice is a block store's own IDs()[i], binding the tag to the
// store's own addressing scheme; the paper's own choice, index i encoded as
// bytes, works equally well.
//
// The algorithm (§4.3 / Fig. 2, TagBlock):
//  1. W_i = v||id; T_{i,m} = (h(W_i) · g^m)^d mod N. (Fig. 2, TagBlock step 1)
//  2. Output T_{i,m}. (Fig. 2, TagBlock step 2; W_i itself is not returned,
//     since CheckProof recomputes it from sk.V and id, see BlockW.)
//
// The tags (but not sk.V) are sent to the server along with the blocks.
func TagBlock(s *suite.Suite, pk *pdp.PublicKey, sk *SecretKey, m []byte, id []byte) (*Tag, error) {
	mInt := new(big.Int).SetBytes(m)
	w := BlockW(sk.V, id)

	h := s.HashToQRN(w, pk.N)                // h(w) ∈ QR_N
	gm := new(big.Int).Exp(pk.G, mInt, pk.N) // g^m mod N
	T := new(big.Int).Mul(gm, h)             // h(w) * g^m
	T.Mod(T, pk.N)
	T.Exp(T, sk.D, pk.N) // (h(w) * g^m)^d mod N

	return &Tag{SuiteID: s.ID(), T: T}, nil
}

// TagFetcher supplies the tag at index i on demand. GenProof only ever
// calls it for the c indices its own index derivation (BuildPRP) selects, so
// a caller can resolve tags via a targeted read per call, for example against
// a partitioned, range-readable storage format, rather than pre-loading every
// tag belonging to the file up front.
type TagFetcher func(i int) (*Tag, error)

// GenProof is run by the server to produce a proof of possession for the challenged blocks.
//
// All tags must carry the same SuiteID as s; GenProof returns an error on any
// mismatch so the server never silently uses the wrong algorithm.
//
// The algorithm (§4.3 / Fig. 2, GenProof):
//  1. For 1 ≤ j ≤ C: i_j = π_{k1}(j) via BuildPRP; a_j = f_{k2}(j) via PRF.
//     (Fig. 2, GenProof step 1)
//  2. T = ∏ tag_{i_j}^{a_j} mod N. (Fig. 2, GenProof step 2)
//  3. μ = Σ a_j · block_{i_j} (as an integer) as an unreduced sum.
//     ρ = SHA-256(g_s^μ mod N), where g_s = chal.Gs = g^s.
//     (Fig. 2, GenProof step 3)
//  4. Return V = (T, ρ). (Fig. 2, GenProof step 4)
//
// tags is called only for the indices this challenge actually samples (i.e.
// perm[0:chal.C], derived below), only once BuildPRP has picked those
// indices, so a caller never needs to derive them itself just to know what
// to fetch. chal.C must be in [1, store.Len()].
func GenProof(s *suite.Suite, pk *pdp.PublicKey, store blocks.BlockStore, chal *Challenge, tags TagFetcher) (*Proof, error) {
	if chal.SuiteID != s.ID() {
		return nil, fmt.Errorf("challenge suite %d does not match suite %d", chal.SuiteID, s.ID())
	}
	if chal.C < 1 || chal.C > store.Len() {
		return nil, fmt.Errorf("challenge C=%d out of range [1, %d]", chal.C, store.Len())
	}

	// §4.3 Fig. 2, GenProof step 1: i_j = π_{k1}(j).
	perm := s.BuildPRP(chal.K1, store.Len())

	T := big.NewInt(1)
	mu := big.NewInt(0)

	for j := 1; j <= chal.C; j++ {
		ij := perm[j-1]
		tag, err := tags(ij)
		if err != nil {
			return nil, fmt.Errorf("ateniese.GenProof: tag %d: %w", ij, err)
		}

		if tag.SuiteID != s.ID() {
			return nil, fmt.Errorf("tag[%d] suite %d does not match suite %d", ij, tag.SuiteID, s.ID())
		}

		aj := s.PRF(chal.K2, j) // a_j = f_{k2}(j), §4.3 Fig. 2 step 1

		// §4.3 Fig. 2, GenProof step 2: T = ∏ tag_{i_j}^{a_j} mod N.
		term := new(big.Int).Exp(tag.T, aj, pk.N)
		T.Mul(T, term)
		T.Mod(T, pk.N)

		// §4.3 Fig. 2, GenProof step 3: accumulate μ = Σ a_j · m_{i_j}.
		block, err := blocks.BlockAt(store, ij)
		if err != nil {
			return nil, fmt.Errorf("ateniese.GenProof: block %d: %w", ij, err)
		}
		mu.Add(mu, new(big.Int).Mul(aj, new(big.Int).SetBytes(block)))
	}

	// §4.3 Fig. 2, GenProof step 3: ρ = SHA-256(g_s^μ mod N).
	gsmu := new(big.Int).Exp(chal.Gs, mu, pk.N)
	rho := sha256.Sum256(gsmu.Bytes())

	return &Proof{T: T, Rho: rho[:]}, nil // §4.3 Fig. 2, GenProof step 4
}

// CheckProof is run by the client to verify a proof returned by the server.
//
// secret is the client's per-challenge secret s (not transmitted to the server).
// chal.Gs must equal pk.G^secret mod N.
//
// Fig. 2's Challenge phase writes sk as (e,v) specifically when passing it to
// CheckProof (step 3), not the full (e,d,v) KeyGen output: CheckProof only
// ever reads sk.E and sk.V here (sk.Phi is used too, but only for the
// Lagrange's-theorem exponent reduction described below, which has no
// counterpart in the paper's own CheckProof). sk.D is never read; only
// TagBlock needs it.
//
// ids is the verifier's own trusted, positional record of block identifiers:
// ids[i] must be the same id TagBlock was called with for position i at setup
// time (e.g. a block store's own IDs() at audit time; see "Block identifiers"
// in the package doc). CheckProof recomputes W_ij = V||ids[ij] and h(W_ij)
// itself via BlockW, exactly as the paper's own CheckProof(pk,sk,chal,V)
// recomputes W_ij = v||ij internally from sk (Definition 4.1, §4.3 Fig. 2),
// rather than trusting an externally supplied tag's claim about which
// identifier occupies a given position.
//
// The verification equation (§4.3 / Fig. 2, CheckProof):
//  1. Unpack chal and proof. (Fig. 2, CheckProof step 1)
//  2. Compute H_prod = ∏ h(W_{i_j})^{a_j} mod N, deriving each W_{i_j} from
//     sk.V and ids[i_j] via BlockW. (Fig. 2, CheckProof step 2)
//     The paper describes iterative division: start with τ = T^e and divide by
//     h(W_{i_j})^{a_j} for each j. Here the denominator product is batched and
//     inverted once, which is algebraically the same result. a_j is reduced
//     mod phi = p'q' here via Lagrange's theorem (see package doc); GenProof
//     does not reduce a_j.
//  3. Recover g^μ = T^e · H_prod^{-1} mod N. (Fig. 2, CheckProof step 2)
//     T^e = ∏(h(W_i)·g^m)^{d·e·a_j} = H_prod · g^μ, since d·e ≡ 1 mod p'q'.
//  4. Check SHA-256((g^μ)^s mod N) = ρ. (Fig. 2, CheckProof step 3)
func CheckProof(s *suite.Suite, pk *pdp.PublicKey, sk *SecretKey, secret *big.Int, ids [][]byte, chal *Challenge, proof *Proof) (bool, error) {
	if chal.SuiteID != s.ID() {
		return false, fmt.Errorf("challenge suite %d does not match suite %d", chal.SuiteID, s.ID())
	}
	if chal.C < 1 || chal.C > len(ids) {
		return false, fmt.Errorf("challenge C=%d out of range [1, %d]", chal.C, len(ids))
	}

	// §4.3 Fig. 2, CheckProof step 1: i_j = π_{k1}(j).
	perm := s.BuildPRP(chal.K1, len(ids))

	// §4.3 Fig. 2, CheckProof step 2: compute H_prod = ∏ h(W_{i_j})^{a_j} mod N.
	// The paper iteratively divides τ = T^e by each h(W)^{a_j}; here the product
	// is accumulated and inverted once, which is algebraically the same result.
	Hprod := big.NewInt(1)
	for j := 1; j <= chal.C; j++ {
		ij := perm[j-1]

		aj := s.PRF(chal.K2, j) // a_j = f_{k2}(j), §4.3 Fig. 2 step 1
		// Lagrange's theorem: |QR_N| = p'q', so h(W)^{a_j} ≡ h(W)^{a_j mod p'q'} mod N.
		// Reducing a_j avoids a large-integer exponentiation. GenProof does not
		// reduce a_j for tag^{a_j}; the same theorem makes both sides agree anyway.
		aj.Mod(aj, sk.Phi)

		w := BlockW(sk.V, ids[ij])
		h := s.HashToQRN(w, pk.N)
		term := new(big.Int).Exp(h, aj, pk.N)
		Hprod.Mul(Hprod, term)
		Hprod.Mod(Hprod, pk.N)
	}

	// §4.3 Fig. 2, CheckProof step 2: recover g^μ = T^e · H_prod^{-1} mod N.
	// T^e = ∏(h(W_i)·g^m)^{d·e·a_j} = H_prod · g^μ, since d·e ≡ 1 mod p'q'.
	Te := new(big.Int).Exp(proof.T, sk.E, pk.N)
	Hinv := new(big.Int).ModInverse(Hprod, pk.N)
	if Hinv == nil {
		return false, fmt.Errorf("H_prod has no inverse mod N")
	}
	gmu := new(big.Int).Mul(Te, Hinv)
	gmu.Mod(gmu, pk.N)

	// §4.3 Fig. 2, CheckProof step 3: check SHA-256((g^μ)^s mod N) = ρ.
	gsmu := new(big.Int).Exp(gmu, secret, pk.N)
	expected := sha256.Sum256(gsmu.Bytes())

	return bytes.Equal(expected[:], proof.Rho), nil
}
