// Public-key SW storage proof scheme (§3.3 of Shacham-Waters ASIACRYPT 2008).
//
// Unlike the §3.2 private-key scheme, anyone who holds the public key can
// verify that the server stores the file. Verification requires evaluating two
// Ate pairings over BN256, which is ~100–1000× slower than Z_p arithmetic.
//
// # Protocol
//
// Key generation: draw secret α ∈ Z_q; compute v = α·G₂. Draw random G₁
// elements u₁,...,uₛ (scalars discarded, so no one knows their discrete logs).
// Choose a random 16-byte file name λ. Public key: (λ, v, u₁,...,uₛ).
//
// Tagging: for each block i with sector values f_{i,j} = sectorElem(block,j) ∈ Z_q,
//
//	σ_i = α·(H(λ‖i) + Σ_j f_{i,j}·u_j) ∈ G₁
//
// where H(λ‖i) = SHA-256(λ‖i) mod q · G₁ (ROM hash to G₁).
//
// Proof (server): given challenge (i_t, ν_t):
//
//	σ   = Σ_t ν_t · σ_{i_t}               ∈ G₁
//	μ_j = Σ_t ν_t · f_{i_t,j} mod q       ∈ Z_q
//
// Verification: check
//
//	e(σ, G₂) == e(Σ_t ν_t·H(λ‖i_t) + Σ_j μ_j·u_j, v)
//
// Correctness: substituting the tag definition into σ and using bilinearity of
// e gives the identity for any honest response.
//
// # Security note on H
//
// H(λ‖i) = sha256(λ‖i) mod q · G₁ maps to a scalar multiple of the generator.
// The discrete log of H(λ‖i) w.r.t. the generator is publicly computable, but
// the discrete log of H(λ‖i) w.r.t. any u_j is sha256(λ‖i) / r_j mod q where
// r_j was discarded — hence unknown. Under the computational Diffie-Hellman
// assumption, this is sufficient for the scheme's security proof.

package sw

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/pinionengineering/storage-proofs/blocks"
)

// PubPublicKey is the public key for the §3.3 BLS-based scheme.
// It is sufficient for verification; the secret scalar α is never included.
type PubPublicKey struct {
	// Name is a 16-byte random file identifier bound into every tag via H(Name‖i).
	// The verifier must know Name to reconstruct H for the challenged indices.
	Name []byte

	// V = α·G₂ is the public verification key derived from the secret α.
	V *bn256.G2

	// U[j] = r_j·G₁ for j = 0,...,S-1. The scalars r_j are drawn at KeyGen
	// and immediately discarded; no one knows their discrete logs afterwards.
	U []*bn256.G1
}

// PubScheme implements the §3.3 public-key SW scheme as a Scheme.
// Holds the secret scalar α so it can tag blocks; Verify uses only PubKey.
type PubScheme struct {
	alpha  *big.Int
	pk     *PubPublicKey
	s, l   int
}

// NewPubScheme generates a fresh PubScheme: secret α, public (v, u₁,...,uₛ, λ).
func NewPubScheme(s, l int) (*PubScheme, error) {
	// Secret scalar α; v = α·G₂.
	alpha, v, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sw.NewPubScheme: alpha: %w", err)
	}

	// u_j: random G₁ elements; the generating scalars are discarded.
	u := make([]*bn256.G1, s)
	for j := range s {
		_, uj, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("sw.NewPubScheme: u[%d]: %w", j, err)
		}
		u[j] = uj
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

// PubKey returns the public key. It is the only information required for
// verification; callers can distribute it to any auditor.
func (ps *PubScheme) PubKey() *PubPublicKey { return ps.pk }

func (ps *PubScheme) Kind() SchemeKind { return PubKind }
func (ps *PubScheme) S() int           { return ps.s }
func (ps *PubScheme) L() int           { return ps.l }

// NewPubSchemeFromKey reconstructs a PubScheme from existing key material
// without generating a new keypair. Used by protocol adapters that rebuild
// scheme state from wire setup payloads. pk may be nil if only s and l are
// needed (e.g. for RespondFetch, which does not use the public key).
func NewPubSchemeFromKey(pk *PubPublicKey, s, l int) *PubScheme {
	return &PubScheme{pk: pk, s: s, l: l}
}

// pubHashG1 returns H(data) = SHA-256(data) mod q · G₁ ∈ G₁.
func pubHashG1(data []byte) *bn256.G1 {
	h := sha256.Sum256(data)
	k := new(big.Int).SetBytes(h[:])
	k.Mod(k, bn256.Order)
	return new(bn256.G1).ScalarBaseMult(k)
}

// blockHashG1ID returns H(name‖id) ∈ G₁ for an arbitrary block identifier id ∈ {0,1}*.
// This is the general form of blockHashG1; any unique byte string may serve as id.
func blockHashG1ID(name, id []byte) *bn256.G1 {
	buf := make([]byte, len(name)+len(id))
	copy(buf, name)
	copy(buf[len(name):], id)
	return pubHashG1(buf)
}

// blockHashG1 returns H(name‖i) ∈ G₁.
func blockHashG1(name []byte, i int) *bn256.G1 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(i))
	return blockHashG1ID(name, buf[:])
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
	return new(big.Int).Mod(new(big.Int).SetBytes(block[start:end]), bn256.Order)
}

// tagBlocksCore computes σ_i = α·(hashBlock(i) + Σ_j f_{i,j}·u_j) ∈ G₁ for each block.
// hashBlock(i) returns H(name‖blockID_i) for whatever block-identifier scheme the caller uses.
func (ps *PubScheme) tagBlocksCore(store blocks.BlockStore, hashBlock func(i int) *bn256.G1) ([][]byte, error) {
	n := store.Len()
	out := make([][]byte, n)
	for i := range n {
		block, err := store.Block(i)
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.TagBlocks: block %d: %w", i, err)
		}
		// acc = H(name‖id_i) + Σ_j f_{i,j}·u_j  (additive G₁ notation)
		acc := hashBlock(i)
		for j := range ps.s {
			fij := pubSectorElem(block, j, ps.s)
			term := new(bn256.G1).ScalarMult(ps.pk.U[j], fij)
			acc = new(bn256.G1).Add(acc, term)
		}
		// σ_i = α · acc
		out[i] = new(bn256.G1).ScalarMult(acc, ps.alpha).Marshal()
	}
	return out, nil
}

// TagBlocks computes σ_i = α·(H(Name‖i) + Σ_j f_{i,j}·u_j) ∈ G₁ for each block.
// Each tag is marshalled as 64 bytes (uncompressed G₁ point).
func (ps *PubScheme) TagBlocks(store blocks.BlockStore) ([][]byte, error) {
	name := ps.pk.Name
	return ps.tagBlocksCore(store, func(i int) *bn256.G1 { return blockHashG1(name, i) })
}

// TagBlocksWith computes σ_i = α·(H(Name‖ids[i]) + Σ_j f_{i,j}·u_j) ∈ G₁ using
// per-block identifiers ids[i] ∈ {0,1}* in place of the default uint64(i).
// This generalises Pub.St (§3.3 of Shacham-Waters 2008) to block stores where
// each block carries its own unique identifier rather than a sequential index.
// ids must have exactly store.Len() entries.
func (ps *PubScheme) TagBlocksWith(store blocks.BlockStore, ids [][]byte) ([][]byte, error) {
	if len(ids) != store.Len() {
		return nil, fmt.Errorf("sw.PubScheme.TagBlocksWith: %d ids for %d blocks", len(ids), store.Len())
	}
	name := ps.pk.Name
	return ps.tagBlocksCore(store, func(i int) *bn256.G1 { return blockHashG1ID(name, ids[i]) })
}

// MakeChallenge generates a fresh challenge with coefficients in Z_q.
// Distinct indices are chosen via a partial Fisher-Yates shuffle.
func (ps *PubScheme) MakeChallenge(n int) (*SWChallenge, error) {
	if n <= 0 {
		return nil, fmt.Errorf("sw.PubScheme.MakeChallenge: n must be positive")
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
	copy(indices, perm[:l])

	coeffs := make([]*big.Int, l)
	for t := range l {
		v, err := rand.Int(rand.Reader, bn256.Order)
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

	var sigmaAcc *bn256.G1
	for t, idx := range chal.Indices {
		if idx < 0 || idx >= len(tags) {
			return nil, fmt.Errorf("sw.PubScheme.RespondFetch: index %d out of range [0, %d)", idx, len(tags))
		}
		nu := chal.Coeffs[t]

		tag := new(bn256.G1)
		if _, err := tag.Unmarshal(tags[idx]); err != nil {
			return nil, fmt.Errorf("sw.PubScheme.RespondFetch: tag[%d]: %w", idx, err)
		}

		term := new(bn256.G1).ScalarMult(tag, nu)
		if sigmaAcc == nil {
			sigmaAcc = term
		} else {
			sigmaAcc = new(bn256.G1).Add(sigmaAcc, term)
		}

		data, err := store.Block(idx)
		if err != nil {
			return nil, fmt.Errorf("sw.PubScheme.RespondFetch: block(%d): %w", idx, err)
		}
		for j := range ps.s {
			fij := pubSectorElem(data, j, ps.s)
			mu[j].Add(mu[j], new(big.Int).Mul(nu, fij))
			mu[j].Mod(mu[j], bn256.Order)
		}
	}

	return &SWProof{Sigma: sigmaAcc.Marshal(), Mu: mu}, nil
}

// Verify calls VerifyPub with the embedded public key.
func (ps *PubScheme) Verify(chal *SWChallenge, proof *SWProof) (bool, error) {
	return VerifyPub(ps.pk, chal, proof)
}

// verifyPubCore performs the pairing check e(σ, G₂) == e(A, v) where
// A = Σ_t ν_t·hashBlock(t) + Σ_j μ_j·u_j. hashBlock(t) returns the G₁ point
// for the t-th challenged block under whatever block-identifier scheme the caller uses.
func verifyPubCore(pk *PubPublicKey, chal *SWChallenge, proof *SWProof, hashBlock func(t int) *bn256.G1) (bool, error) {
	if len(proof.Mu) != len(pk.U) {
		return false, fmt.Errorf("sw.VerifyPub: proof has %d μ elements, want %d", len(proof.Mu), len(pk.U))
	}

	sigma := new(bn256.G1)
	if _, err := sigma.Unmarshal(proof.Sigma); err != nil {
		return false, fmt.Errorf("sw.VerifyPub: sigma: %w", err)
	}

	// A = Σ_t ν_t·H(Name‖id_t) + Σ_j μ_j·u_j  ∈ G₁
	var a *bn256.G1
	for t := range chal.Indices {
		nu := chal.Coeffs[t]
		term := new(bn256.G1).ScalarMult(hashBlock(t), nu)
		if a == nil {
			a = term
		} else {
			a = new(bn256.G1).Add(a, term)
		}
	}
	for j, uj := range pk.U {
		term := new(bn256.G1).ScalarMult(uj, proof.Mu[j])
		if a == nil {
			a = term
		} else {
			a = new(bn256.G1).Add(a, term)
		}
	}

	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	lhs := bn256.Pair(sigma, g2)
	rhs := bn256.Pair(a, pk.V)

	return bytes.Equal(lhs.Marshal(), rhs.Marshal()), nil
}

// VerifyPub performs public verification given only the public key.
// This is the distinguishing property of §3.3: anyone who holds pk can audit
// the server without access to the secret scalar α.
//
// Checks: e(σ, G₂) == e(Σ_t ν_t·H(Name‖i_t) + Σ_j μ_j·u_j, v)
func VerifyPub(pk *PubPublicKey, chal *SWChallenge, proof *SWProof) (bool, error) {
	return verifyPubCore(pk, chal, proof, func(t int) *bn256.G1 {
		return blockHashG1(pk.Name, chal.Indices[t])
	})
}

// VerifyPubWith is the Pub.V algorithm (§3.3) with caller-supplied per-block
// identifiers ids[t] ∈ {0,1}* for the t-th challenged block, in place of the
// default uint64(chal.Indices[t]). This is valid because §3.3 defines
// H : {0,1}* → G as a random oracle over arbitrary bit strings; any unique
// identifier may serve as input. ids must have exactly len(chal.Indices) entries,
// matching those passed to TagBlocksWith at tag time.
func VerifyPubWith(pk *PubPublicKey, chal *SWChallenge, proof *SWProof, ids [][]byte) (bool, error) {
	if len(ids) != len(chal.Indices) {
		return false, fmt.Errorf("sw.VerifyPubWith: %d ids for %d challenged blocks", len(ids), len(chal.Indices))
	}
	return verifyPubCore(pk, chal, proof, func(t int) *bn256.G1 {
		return blockHashG1ID(pk.Name, ids[t])
	})
}
