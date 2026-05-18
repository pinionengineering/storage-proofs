// Package swpub wires the Shacham-Waters public-key POR (§3.3) to the line
// protocol interfaces. Challenges and proofs are JSON-encoded byte slices.
//
// Unlike the private-key variant (line/sw), any party holding the public key
// can verify proofs. Verification uses two BN256 Ate pairings, which is
// significantly slower than the Z_p arithmetic in the private-key scheme.
package swpub

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
)

// ---------------------------------------------------------------------------
// Wire types (JSON)
// ---------------------------------------------------------------------------

// G1 points marshal to 64 bytes; G2 points to 128 bytes.
// big.Int scalars in Z_q are serialized as fixed 32-byte big-endian.

type wireChal struct {
	Indices []int    `json:"indices"`
	Coeffs  [][]byte `json:"coeffs"` // len(l) × 32 bytes, Z_q scalars
}

type wireProof struct {
	Sigma []byte   `json:"sigma"` // 64-byte G1 point
	Mu    [][]byte `json:"mu"`    // len(s) × 32 bytes, Z_q scalars
}

type wireClientSetup struct {
	Protocol string   `json:"protocol"`
	S        int      `json:"s"`
	L        int      `json:"l"`
	Name     []byte   `json:"name"` // 16 bytes
	V        []byte   `json:"v"`    // 128 bytes, G2
	U        [][]byte `json:"u"`    // s × 64 bytes, G1
}

type wireProverSetup struct {
	Protocol string   `json:"protocol"`
	S        int      `json:"s"`
	Tags     [][]byte `json:"tags"` // n × 64 bytes, G1
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bigToFixed32(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func fixed32ToBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// ---------------------------------------------------------------------------
// Tagger (implements line.Tagger and line.SetupProducer)
// ---------------------------------------------------------------------------

// Tagger creates per-block G1 tags and produces client/prover setup blobs.
type Tagger struct {
	ps    *porsw.PubScheme
	store blocks.BlockStore // cached after TagBlocks
	tags  [][]byte          // raw 64-byte G1 marshals, set after TagBlocks
}

func NewTagger(ps *porsw.PubScheme) *Tagger { return &Tagger{ps: ps} }

func (t *Tagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	raw, err := t.ps.TagFile(store)
	if err != nil {
		return nil, fmt.Errorf("swpub.TagBlocks: %w", err)
	}
	t.store = store
	t.tags = raw
	out := make([]line.Tag, len(raw))
	for i, b := range raw {
		out[i] = line.Tag(b)
	}
	return out, nil
}

func (t *Tagger) ClientSetup() ([]byte, error) {
	pk := t.ps.PubKey()
	u := make([][]byte, len(pk.U))
	for j, uj := range pk.U {
		u[j] = uj.Marshal()
	}
	return json.Marshal(wireClientSetup{
		Protocol: "swpub",
		S:        t.ps.S(),
		L:        t.ps.L(),
		Name:     pk.Name,
		V:        pk.V.Marshal(),
		U:        u,
	})
}

func (t *Tagger) ProverSetup() ([]byte, error) {
	return json.Marshal(wireProverSetup{
		Protocol: "swpub",
		S:        t.ps.S(),
		Tags:     t.tags,
	})
}

// EncodedBlocks returns the original store; SW-Pub does not transform blocks.
func (t *Tagger) EncodedBlocks() blocks.BlockStore { return t.store }

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory for the SW-Pub scheme.
// c is ignored; the challenge size is fixed by L stored in the setup blob.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, _ int) (line.Challenger, error) {
	var ws wireClientSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("swpub.NewChallenger: %w", err)
	}
	v := new(bn256.G2)
	if _, err := v.Unmarshal(ws.V); err != nil {
		return nil, fmt.Errorf("swpub.NewChallenger: V: %w", err)
	}
	u := make([]*bn256.G1, len(ws.U))
	for j, raw := range ws.U {
		u[j] = new(bn256.G1)
		if _, err := u[j].Unmarshal(raw); err != nil {
			return nil, fmt.Errorf("swpub.NewChallenger: U[%d]: %w", j, err)
		}
	}
	pk := &porsw.PubPublicKey{Name: ws.Name, V: v, U: u}
	return &Challenger{pk: pk, s: ws.S, l: ws.L}, nil
}

// ---------------------------------------------------------------------------
// ProverFactory
// ---------------------------------------------------------------------------

type proverFactory struct{}

// NewProverFactory returns a ProverFactory for the SW-Pub scheme.
func NewProverFactory() line.ProverFactory { return proverFactory{} }

func (proverFactory) NewProver(setup []byte, _ blocks.BlockStore) (line.Prover, error) {
	var ws wireProverSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("swpub.NewProver: %w", err)
	}
	return &Prover{s: ws.S, tags: ws.Tags}, nil
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger implements line.Challenger for the SW public-key scheme.
type Challenger struct {
	pk *porsw.PubPublicKey
	s  int
	l  int
}

// ChalBytes returns the binary size of a challenge: C*(index+32-byte coeff).
func (ch *Challenger) ChalBytes(chal line.Challenge) int {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return len(chal)
	}
	n := 4 * len(wc.Indices)
	for _, c := range wc.Coeffs {
		n += len(c)
	}
	return n
}

func (ch *Challenger) Challenge(numBlocks int) (line.Challenge, line.Validator, error) {
	// MakeChallenge only reads ps.l; no keypair needed.
	ps := porsw.NewPubSchemeFromKey(nil, ch.s, ch.l)
	chal, err := ps.MakeChallenge(numBlocks)
	if err != nil {
		return nil, nil, fmt.Errorf("swpub.Challenge: %w", err)
	}
	coeffs := make([][]byte, len(chal.Coeffs))
	for i, c := range chal.Coeffs {
		coeffs[i] = bigToFixed32(c)
	}
	b, err := json.Marshal(wireChal{Indices: chal.Indices, Coeffs: coeffs})
	if err != nil {
		return nil, nil, fmt.Errorf("swpub.Challenge: marshal: %w", err)
	}
	return line.Challenge(b), &Validator{pk: ch.pk, raw: chal}, nil
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

// Prover implements line.Prover for the SW public-key scheme.
// It holds the per-block G1 tags produced by TagBlocks.
type Prover struct {
	s    int
	tags [][]byte // n × 64-byte G1 marshals
}

// ProofBytes returns the binary size of a proof: 64-byte G1 sigma plus
// 32-byte-per-element mu scalars.
func (p *Prover) ProofBytes(proof line.Proof) int {
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return len(proof)
	}
	n := len(wp.Sigma)
	for _, m := range wp.Mu {
		n += len(m)
	}
	return n
}

func (p *Prover) Prove(chal line.Challenge, store blocks.BlockStore) (line.Proof, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return nil, fmt.Errorf("swpub.Prove: challenge: %w", err)
	}
	coeffs := make([]*big.Int, len(wc.Coeffs))
	for i, c := range wc.Coeffs {
		coeffs[i] = fixed32ToBig(c)
	}
	swChal := &porsw.SWChallenge{Kind: porsw.PubKind, Indices: wc.Indices, Coeffs: coeffs}
	// RespondFetch only reads ps.s from the scheme; no keypair needed.
	resp, err := porsw.NewPubSchemeFromKey(nil, p.s, 0).RespondFetch(p.tags, swChal, store)
	if err != nil {
		return nil, fmt.Errorf("swpub.Prove: %w", err)
	}
	mu := make([][]byte, len(resp.Mu))
	for j, mj := range resp.Mu {
		mu[j] = bigToFixed32(mj)
	}
	b, err := json.Marshal(wireProof{Sigma: resp.Sigma, Mu: mu})
	if err != nil {
		return nil, fmt.Errorf("swpub.Prove: marshal: %w", err)
	}
	return line.Proof(b), nil
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

// Validator implements line.Validator for the SW public-key scheme.
type Validator struct {
	pk  *porsw.PubPublicKey
	raw *porsw.SWChallenge // bound to one challenge round
}

func (v *Validator) Verify(_ line.Challenge, proof line.Proof) (bool, error) {
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return false, fmt.Errorf("swpub.Verify: proof: %w", err)
	}
	mu := make([]*big.Int, len(wp.Mu))
	for j, m := range wp.Mu {
		mu[j] = fixed32ToBig(m)
	}
	swProof := &porsw.SWProof{Sigma: wp.Sigma, Mu: mu}
	return porsw.VerifyPub(v.pk, v.raw, swProof)
}
