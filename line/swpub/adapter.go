// Package swpub wires the Shacham-Waters public-key POR (§3.3) to the line
// protocol interfaces. Challenges and proofs are JSON-encoded byte slices.
//
// Unlike the private-key variant (line/sw), any party holding the public key
// can verify proofs. Verification uses two BN256 Ate pairings, which is
// significantly slower than the Z_p arithmetic in the private-key scheme.
package swpub

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

// ---------------------------------------------------------------------------
// Wire types (JSON)
// ---------------------------------------------------------------------------

// G1 points marshal to 64 bytes; G2 points to 128 bytes.
// big.Int scalars in Z_q are serialized as fixed 32-byte big-endian.

type wireChal struct {
	SuiteID uint8  `json:"suite_id"`
	Seed    []byte `json:"seed"`
	C       int    `json:"c"`
	N       int    `json:"n"`
}

type wireProof struct {
	Sigma []byte   `json:"sigma"` // 64-byte G1 point
	Mu    [][]byte `json:"mu"`    // len(s) × 32 bytes, Z_q scalars
}

type wireClientSetup struct {
	Protocol string   `json:"protocol"`
	SuiteID  uint8    `json:"suite_id"`
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
	s     *suite.Suite
	store blocks.BlockStore // cached after TagBlocks
	tags  [][]byte          // raw 64-byte G1 marshals, set after TagBlocks
}

func NewTagger(ps *porsw.PubScheme, s *suite.Suite) *Tagger { return &Tagger{ps: ps, s: s} }

func (t *Tagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	raw, err := t.ps.TagBlocks(store)
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
		SuiteID:  t.s.ID(),
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
	s, ok := suite.SuiteByID(ws.SuiteID)
	if !ok {
		return nil, fmt.Errorf("swpub.NewChallenger: unknown suite %d", ws.SuiteID)
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
	return &Challenger{pk: pk, suite: s, s: ws.S, l: ws.L}, nil
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
	pk    *porsw.PubPublicKey
	suite *suite.Suite
	s     int
	l     int
}

// ChalBytes returns the binary size of a compact seed challenge: 1+32+4+4 = 41 bytes.
func (ch *Challenger) ChalBytes(_ line.Challenge) int {
	return 41
}

func (ch *Challenger) Challenge(ids [][]byte) (line.Challenge, line.Validator, error) {
	c := ch.l
	if c > len(ids) {
		c = len(ids)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("swpub.Challenge: seed: %w", err)
	}
	b, err := json.Marshal(wireChal{SuiteID: ch.suite.ID(), Seed: seed, C: c, N: len(ids)})
	if err != nil {
		return nil, nil, fmt.Errorf("swpub.Challenge: marshal: %w", err)
	}
	return line.Challenge(b), &Validator{pk: ch.pk}, nil
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
	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return nil, fmt.Errorf("swpub.Prove: unknown suite %d", wc.SuiteID)
	}
	ids := make([][]byte, wc.N)
	for i := range wc.N {
		ids[i] = blocks.IntID(i)
	}
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, ids, wc.C, bn256.Order)
	swChal := &porsw.SWChallenge{Kind: porsw.PubKind, Indices: indices, Coeffs: coeffs}
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
// It is stateless: (seed, C, N) in the wire challenge are used to re-derive
// the indices and coefficients at verify time per §3.3.
type Validator struct {
	pk *porsw.PubPublicKey
}

func (v *Validator) Verify(chal line.Challenge, proof line.Proof) (bool, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return false, fmt.Errorf("swpub.Verify: challenge: %w", err)
	}
	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return false, fmt.Errorf("swpub.Verify: unknown suite %d", wc.SuiteID)
	}
	ids := make([][]byte, wc.N)
	for i := range wc.N {
		ids[i] = blocks.IntID(i)
	}
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, ids, wc.C, bn256.Order)
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return false, fmt.Errorf("swpub.Verify: proof: %w", err)
	}
	mu := make([]*big.Int, len(wp.Mu))
	for j, m := range wp.Mu {
		mu[j] = fixed32ToBig(m)
	}
	swChal := &porsw.SWChallenge{Kind: porsw.PubKind, Indices: indices, Coeffs: coeffs}
	return porsw.VerifyPub(v.pk, swChal, &porsw.SWProof{Sigma: wp.Sigma, Mu: mu}, ids)
}
