// Public-key SW storage proof scheme (§3.3 of Shacham-Waters ASIACRYPT 2008).
//
// Unlike the §3.2 private-key scheme, anyone who holds the public key can
// verify that the server stores the file. Verification requires evaluating two
// Ate pairings over BN254 (Ethereum alt_bn128).
//
// # Protocol
//
// Key generation: draw secret α ∈ Z_q; compute v = α·G₂. Draw random G₁
// elements u₁,...,uₛ (scalars discarded, so no one knows their discrete logs).
// Choose a random 16-byte file name λ. Public key: (λ, v, u₁,...,uₛ).
//
// Tagging: for each block i with sector values f_{i,j} = sectorElem(block,j) ∈ Z_q,
//
//	σ_i = α·(H(λ‖id_i) + Σ_j f_{i,j}·u_j) ∈ G₁
//
// where H(λ‖id_i) = HashToG1(λ‖id_i) via RFC 9380 SVDW with DST
// "sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_" (see pubHashG1).
//
// Proof (server): given challenge (id_t, ν_t):
//
//	σ   = Σ_t ν_t · σ_{i_t}               ∈ G₁
//	μ_j = Σ_t ν_t · f_{i_t,j} mod q       ∈ Z_q
//
// Verification: check
//
//	e(σ, G₂) == e(Σ_t ν_t·H(λ‖id_t) + Σ_j μ_j·u_j, v)
//
// Correctness: substituting the tag definition into σ and using bilinearity of
// e gives the identity for any honest response.
//
// # Security note on H
//
// H(λ‖id) = sha256(λ‖id) mod q · G₁ maps to a scalar multiple of the generator.
// The discrete log of H(λ‖id) w.r.t. the generator is publicly computable, but
// the discrete log of H(λ‖id) w.r.t. any u_j is sha256(λ‖id) / r_j mod q where
// r_j was discarded — hence unknown. Under the computational Diffie-Hellman
// assumption, this is sufficient for the scheme's security proof.

package sw

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/pinionengineering/storage-proofs/blocks"
)

// bn254Order is the BN254 (alt_bn128) group order, cached at package init.
var bn254Order = fr.Modulus()

// PubPublicKey is the public key for the §3.3 BLS-based scheme.
// It is sufficient for verification; the secret scalar α is never included.
type PubPublicKey struct {
	// Name is a 16-byte random file identifier bound into every tag via H(Name‖id).
	// The verifier must know Name to reconstruct H for the challenged identifiers.
	Name []byte

	// V = α·G₂ is the public verification key derived from the secret α.
	V bn254.G2Affine

	// U[j] = r_j·G₁ for j = 0,...,S-1. The scalars r_j are drawn at KeyGen
	// and immediately discarded; no one knows their discrete logs afterwards.
	U []bn254.G1Affine
}

// PubScheme implements the §3.3 public-key SW scheme as a Scheme.
// Holds the secret scalar α so it can tag blocks; Verify uses only PubKey.
type PubScheme struct {
	alpha *big.Int
	pk    *PubPublicKey
	s, l  int
}

// NewPubScheme generates a fresh PubScheme: secret α, public (v, u₁,...,uₛ, λ).
func NewPubScheme(s, l int) (*PubScheme, error) {
	alpha, err := rand.Int(rand.Reader, bn254Order)
	if err != nil {
		return nil, fmt.Errorf("sw.NewPubScheme: alpha: %w", err)
	}
	var v bn254.G2Affine
	v.ScalarMultiplicationBase(alpha)

	u := make([]bn254.G1Affine, s)
	for j := range s {
		r, err := rand.Int(rand.Reader, bn254Order)
		if err != nil {
			return nil, fmt.Errorf("sw.NewPubScheme: u[%d]: %w", j, err)
		}
		u[j].ScalarMultiplicationBase(r)
	}

	name := make([]byte, 16)
	if _, err := rand.Read(name); err != nil {
		return nil, fmt.Errorf("sw.NewPubScheme: name: %w", err)
	}

	return &PubScheme{
		alpha: alpha,
		pk:    &PubPublicKey{Name: name, V: v, U: u},
		s:     s,
		l:     l,
	}, nil
}

// PubKey returns the public key.
func (ps *PubScheme) PubKey() *PubPublicKey { return ps.pk }

func (ps *PubScheme) Kind() SchemeKind { return PubKind }
func (ps *PubScheme) S() int           { return ps.s }
func (ps *PubScheme) L() int           { return ps.l }

// MarshalJSON implements json.Marshaler. Includes the secret α (fixed 32-byte
// big-endian), public key (v, u₁,...,uₛ, name), and scheme parameters (s, l).
func (ps PubScheme) MarshalJSON() ([]byte, error) {
	u := make([][]byte, len(ps.pk.U))
	for j := range ps.pk.U {
		raw := ps.pk.U[j].RawBytes()
		u[j] = raw[:]
	}
	vRaw := ps.pk.V.RawBytes()
	type wire struct {
		S     int      `json:"s"`
		L     int      `json:"l"`
		Name  []byte   `json:"name"`
		V     []byte   `json:"v"`
		U     [][]byte `json:"u"`
		Alpha []byte   `json:"alpha"` // secret α, fixed 32-byte big-endian
	}
	ab := ps.alpha.Bytes()
	fixed := make([]byte, 32)
	copy(fixed[32-len(ab):], ab)
	return json.Marshal(wire{
		S: ps.s, L: ps.l,
		Name:  ps.pk.Name,
		V:     vRaw[:],
		U:     u,
		Alpha: fixed,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (ps *PubScheme) UnmarshalJSON(data []byte) error {
	type wire struct {
		S     int      `json:"s"`
		L     int      `json:"l"`
		Name  []byte   `json:"name"`
		V     []byte   `json:"v"`
		U     [][]byte `json:"u"`
		Alpha []byte   `json:"alpha"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("sw.PubScheme: %w", err)
	}
	var v bn254.G2Affine
	if _, err := v.SetBytes(w.V); err != nil {
		return fmt.Errorf("sw.PubScheme: V: %w", err)
	}
	u := make([]bn254.G1Affine, len(w.U))
	for j, raw := range w.U {
		if _, err := u[j].SetBytes(raw); err != nil {
			return fmt.Errorf("sw.PubScheme: U[%d]: %w", j, err)
		}
	}
	ps.alpha = new(big.Int).SetBytes(w.Alpha)
	ps.pk = &PubPublicKey{Name: w.Name, V: v, U: u}
	ps.s = w.S
	ps.l = w.L
	return nil
}

// NewPubSchemeFromKey reconstructs a PubScheme from existing key material
// without generating a new keypair. Used by protocol adapters that rebuild
// scheme state from wire setup payloads. pk may be nil if only s and l are
// needed (e.g. for RespondFetch, which does not use the public key).
func NewPubSchemeFromKey(pk *PubPublicKey, s, l int) *PubScheme {
	return &PubScheme{pk: pk, s: s, l: l}
}

// pubHashDST is the RFC 9380 domain separation tag for the SW §3.3 hash-to-G₁
// operation. Changing this value invalidates all previously stored tags.
var pubHashDST = []byte("sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_")

// pubHashG1 returns H(data) ∈ G₁ via the RFC 9380 hash-to-curve map (SVDW).
// The output is indistinguishable from a uniform G₁ point (random oracle).
func pubHashG1(data []byte) (bn254.G1Affine, error) {
	return bn254.HashToG1(data, pubHashDST)
}

// blockHashG1 returns H(name‖id) ∈ G₁ for an arbitrary block identifier id.
func blockHashG1(name, id []byte) (bn254.G1Affine, error) {
	buf := make([]byte, len(name)+len(id))
	copy(buf, name)
	copy(buf[len(name):], id)
	return pubHashG1(buf)
}

// pubSectorElem extracts sector j of block as an element of Z_q (curve order).
func pubSectorElem(block []byte, j, s int) *big.Int {
	n := len(block)
	sz := (n + s - 1) / s
	start := j * sz
	if start >= n {
		return big.NewInt(0)
	}
	end := start + sz
	if end > n {
		end = n
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(block[start:end]), bn254Order)
}

// TagBlocks computes σ_i = α·(H(Name‖id_i) + Σ_j f_{i,j}·u_j) ∈ G₁ for each block.
// Each tag is marshalled as 64 bytes (uncompressed G₁ point).
func (ps *PubScheme) TagBlocks(store blocks.BlockStore) ([][]byte, error) {
	ids := store.IDs()
	out := make([][]byte, len(ids))
	for i, id := range ids {
		block, err := store.Block(id)
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.TagBlocks: block %d: %w", i, err)
		}
		acc, err := blockHashG1(ps.pk.Name, id)
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.TagBlocks: hash block %d: %w", i, err)
		}
		for j := range ps.s {
			fij := pubSectorElem(block, j, ps.s)
			var term bn254.G1Affine
			term.ScalarMultiplication(&ps.pk.U[j], fij)
			acc.Add(&acc, &term)
		}
		var tag bn254.G1Affine
		tag.ScalarMultiplication(&acc, ps.alpha)
		raw := tag.RawBytes()
		out[i] = raw[:]
	}
	return out, nil
}

// MakeChallenge generates a fresh challenge with coefficients in Z_q.
// Distinct IDs are chosen via a partial Fisher-Yates shuffle over index positions.
func (ps *PubScheme) MakeChallenge(ids [][]byte) (*SWChallenge, error) {
	n := len(ids)
	if n <= 0 {
		return nil, fmt.Errorf("sw.PubScheme.MakeChallenge: ids must be non-empty")
	}
	l := ps.l
	if l > n {
		l = n
	}

	perm := make([]int, n)
	for i := range n {
		perm[i] = i
	}
	for i := range l {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(n-i)))
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.MakeChallenge: index %d: %w", i, err)
		}
		j := i + int(jBig.Int64())
		perm[i], perm[j] = perm[j], perm[i]
	}

	indices := make([]int, l)
	for i := range l {
		indices[i] = perm[i]
	}

	coeffs := make([]*big.Int, l)
	for t := range l {
		v, err := rand.Int(rand.Reader, bn254Order)
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.MakeChallenge: coeff %d: %w", t, err)
		}
		coeffs[t] = v
	}

	return &SWChallenge{Kind: PubKind, Indices: indices, Coeffs: coeffs}, nil
}

// RespondFetch computes:
//
//	σ   = Σ_t ν_t · σ_{i_t}           ∈ G₁
//	μ_j = Σ_t ν_t · f_{i_t,j} mod q   ∈ Z_q
func (ps *PubScheme) RespondFetch(tags [][]byte, chal *SWChallenge, store blocks.BlockStore) (*SWProof, error) {
	if len(chal.Indices) == 0 {
		return nil, fmt.Errorf("sw.PubScheme.RespondFetch: empty challenge")
	}

	mu := make([]*big.Int, ps.s)
	for j := range ps.s {
		mu[j] = big.NewInt(0)
	}

	var sigmaAcc bn254.G1Affine // zero value = identity
	for t, idx := range chal.Indices {
		if idx < 0 || idx >= len(tags) {
			return nil, fmt.Errorf("sw.PubScheme.RespondFetch: index %d out of range [0, %d)", idx, len(tags))
		}
		nu := chal.Coeffs[t]

		var tag bn254.G1Affine
		if _, err := tag.SetBytes(tags[idx]); err != nil {
			return nil, fmt.Errorf("sw.PubScheme.RespondFetch: tag[%d]: %w", idx, err)
		}
		var term bn254.G1Affine
		term.ScalarMultiplication(&tag, nu)
		sigmaAcc.Add(&sigmaAcc, &term)

		data, err := blocks.BlockAt(store, idx)
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.RespondFetch: block %d: %w", idx, err)
		}
		for j := range ps.s {
			fij := pubSectorElem(data, j, ps.s)
			mu[j].Add(mu[j], new(big.Int).Mul(nu, fij))
			mu[j].Mod(mu[j], bn254Order)
		}
	}

	raw := sigmaAcc.RawBytes()
	return &SWProof{Sigma: raw[:], Mu: mu}, nil
}

// Verify calls VerifyPub with the embedded public key.
func (ps *PubScheme) Verify(chal *SWChallenge, proof *SWProof, ids [][]byte) (bool, error) {
	return VerifyPub(ps.pk, chal, proof, ids)
}

// verifyPubCore performs the pairing check:
//
//	e(σ, G₂) == e(A, v)
//
// where A = Σ_t ν_t·H(Name‖id_t) + Σ_j μ_j·u_j. Implemented as
// PairingCheck([σ, -A], [G₂, v]) == true for efficiency (one multi-pairing).
func verifyPubCore(pk *PubPublicKey, chal *SWChallenge, proof *SWProof, ids [][]byte) (bool, error) {
	if len(proof.Mu) != len(pk.U) {
		return false, fmt.Errorf("sw.VerifyPub: proof has %d μ elements, want %d", len(proof.Mu), len(pk.U))
	}

	var sigma bn254.G1Affine
	if _, err := sigma.SetBytes(proof.Sigma); err != nil {
		return false, fmt.Errorf("sw.VerifyPub: sigma: %w", err)
	}

	// A = Σ_t ν_t·H(Name‖id_t) + Σ_j μ_j·u_j  ∈ G₁
	var a bn254.G1Affine // zero = identity
	for t, idx := range chal.Indices {
		nu := chal.Coeffs[t]
		h, err := blockHashG1(pk.Name, ids[idx])
		if err != nil {
			return false, fmt.Errorf("sw.VerifyPub: hash block %d: %w", idx, err)
		}
		var term bn254.G1Affine
		term.ScalarMultiplication(&h, nu)
		a.Add(&a, &term)
	}
	for j := range pk.U {
		var term bn254.G1Affine
		term.ScalarMultiplication(&pk.U[j], proof.Mu[j])
		a.Add(&a, &term)
	}

	var negA bn254.G1Affine
	negA.Neg(&a)
	_, _, _, g2Gen := bn254.Generators()
	return bn254.PairingCheck(
		[]bn254.G1Affine{sigma, negA},
		[]bn254.G2Affine{g2Gen, pk.V},
	)
}

// VerifyPub performs public verification given only the public key.
// This is the distinguishing property of §3.3: anyone who holds pk can audit
// the server without access to the secret scalar α.
//
// Checks: e(σ, G₂) == e(Σ_t ν_t·H(λ‖id_t) + Σ_j μ_j·u_j, v)
func VerifyPub(pk *PubPublicKey, chal *SWChallenge, proof *SWProof, ids [][]byte) (bool, error) {
	return verifyPubCore(pk, chal, proof, ids)
}
