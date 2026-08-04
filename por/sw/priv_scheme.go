package sw

import (
	"fmt"
	"math/big"

	"github.com/pinionengineering/storage-proofs/blocks"
	suitemod "github.com/pinionengineering/storage-proofs/suite"
)

// PrivScheme wraps the §3.2 private-key scheme and implements the Scheme interface.
// Create with NewPrivScheme; the embedded secret key is used for tagging and
// verification.
type PrivScheme struct {
	suite *suitemod.Suite
	sk    *SecretKey
}

// NewPrivScheme runs KeyGen and returns a ready PrivScheme.
func NewPrivScheme(s *suitemod.Suite, params *Params) (*PrivScheme, error) {
	sk, err := KeyGen(params)
	if err != nil {
		return nil, fmt.Errorf("sw.NewPrivScheme: %w", err)
	}
	return &PrivScheme{suite: s, sk: sk}, nil
}

func (ps *PrivScheme) Kind() SchemeKind { return PrivKind }

// TagBlocks serializes each tag as big-endian Z_P bytes.
func (ps *PrivScheme) TagBlocks(store blocks.BlockStore) ([][]byte, error) {
	tags, err := TagBlocks(ps.suite, ps.sk, store)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(tags))
	for i, t := range tags {
		out[i] = t.Sigma.Bytes()
	}
	return out, nil
}

// MakeChallenge generates a fresh challenge with coefficients in Z_P.
// ids is store.IDs() from the store being audited; len(ids) is used as n (§3.2).
func (ps *PrivScheme) MakeChallenge(ids [][]byte, l int) (*SWChallenge, error) {
	c, err := MakeChallenge(ids, ps.sk.Params, l)
	if err != nil {
		return nil, err
	}
	return &SWChallenge{Kind: PrivKind, Indices: c.Indices, Coeffs: c.Coeffs}, nil
}

// RespondFetch deserializes the tags, computes the proof, and re-serializes
// sigma. tags is keyed by block index, so the caller only needs to supply
// tags for the indices chal.Indices names.
func (ps *PrivScheme) RespondFetch(tags map[int][]byte, chal *SWChallenge, store blocks.BlockStore) (*SWProof, error) {
	privTags := make(map[int]*Tag, len(tags))
	for i, b := range tags {
		privTags[i] = &Tag{Sigma: new(big.Int).SetBytes(b)}
	}
	c := &Challenge{Indices: chal.Indices, Coeffs: chal.Coeffs}
	p, err := RespondFetch(ps.sk.Params, privTags, c, store)
	if err != nil {
		return nil, err
	}
	return &SWProof{Sigma: p.Sigma.Bytes(), Mu: p.Mu}, nil
}

// Verify reconstructs sigma from the secret key and compares it to the proof.
// ids is store.IDs() from the audited store; the PRF input for each challenged
// block is its raw identifier bytes, matching what TagBlocks computed.
func (ps *PrivScheme) Verify(chal *SWChallenge, proof *SWProof, ids [][]byte) (bool, error) {
	c := &Challenge{Indices: chal.Indices, Coeffs: chal.Coeffs}
	p := &Proof{Sigma: new(big.Int).SetBytes(proof.Sigma), Mu: proof.Mu}
	return Verify(ps.suite, ps.sk, ids, c, p)
}
