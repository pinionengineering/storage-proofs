// Package sw wires the Shacham-Waters private-key POR math (por/sw) to the
// protocol interfaces. Challenges and proofs are JSON-encoded byte slices.
package sw

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/confidence"
	"github.com/pinionengineering/storage-proofs/line"
	"github.com/pinionengineering/storage-proofs/suite"
)

// ---------------------------------------------------------------------------
// Wire types (JSON, provisional)
// ---------------------------------------------------------------------------

type wireChal struct {
	SuiteID uint8  `json:"suite_id"`
	Seed    []byte `json:"seed"`
	C       int    `json:"c"`
	N       int    `json:"n"`
}

type wireTag struct {
	Sigma *big.Int `json:"sigma"`
}

type wireProof struct {
	Sigma *big.Int   `json:"sigma"`
	Mu    []*big.Int `json:"mu"`
}

// ---------------------------------------------------------------------------
// Tagger
// ---------------------------------------------------------------------------

// Tagger implements line.Tagger and line.SetupProducer for the SW scheme.
type Tagger struct {
	sk    *porsw.SecretKey
	s     *suite.Suite
	store blocks.BlockStore // cached after TagBlocks
	tags  []line.Tag        // cached after TagBlocks
}

func NewTagger(sk *porsw.SecretKey, s *suite.Suite) *Tagger {
	return &Tagger{sk: sk, s: s}
}

func (t *Tagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	raw, err := porsw.TagBlocks(t.s, t.sk, store)
	if err != nil {
		return nil, fmt.Errorf("sw.TagBlocks: %w", err)
	}
	tags := make([]line.Tag, len(raw))
	for i, tag := range raw {
		b, err := json.Marshal(wireTag{Sigma: tag.Sigma})
		if err != nil {
			return nil, fmt.Errorf("sw.TagBlocks[%d]: %w", i, err)
		}
		tags[i] = line.Tag(b)
	}
	t.store = store
	t.tags = tags
	return tags, nil
}

// ---------------------------------------------------------------------------
// SetupProducer (Tagger implements line.SetupProducer)
// ---------------------------------------------------------------------------

type wireSetup struct {
	Protocol string     `json:"protocol"`
	S        int        `json:"sw_s"`
	L        int        `json:"sw_l"`
	P        *big.Int   `json:"sw_p"`
	Tags     []line.Tag `json:"tags"`
}

type wireClientSetup struct {
	Protocol string     `json:"protocol"`
	SuiteID  uint8      `json:"suite_id"`
	K        []byte     `json:"sk_k"`
	Alpha    []*big.Int `json:"sk_alpha"`
	S        int        `json:"params_s"`
	L        int        `json:"params_l"`
	P        *big.Int   `json:"params_p"`
}

func (t *Tagger) ProverSetup() ([]byte, error) {
	p := t.sk.Params
	return json.Marshal(wireSetup{Protocol: "sw", S: p.S, L: p.L, P: p.P, Tags: t.tags})
}

func (t *Tagger) ClientSetup() ([]byte, error) {
	p := t.sk.Params
	return json.Marshal(wireClientSetup{
		Protocol: "sw",
		SuiteID:  t.s.ID(),
		K:        t.sk.K,
		Alpha:    t.sk.Alpha,
		S:        p.S, L: p.L, P: p.P,
	})
}

func (t *Tagger) EncodedBlocks() blocks.BlockStore { return t.store }

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory that reconstructs an sw
// Challenger from a blob produced by Tagger.ClientSetup. c is ignored; the
// challenge block count is fixed by the Params.L stored in the setup blob.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, _ int) (line.Challenger, error) {
	var ws wireClientSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("sw.NewChallenger: %w", err)
	}
	s, ok := suite.SuiteByID(ws.SuiteID)
	if !ok {
		return nil, fmt.Errorf("sw.NewChallenger: unknown suite %d", ws.SuiteID)
	}
	sk := &porsw.SecretKey{
		K:      ws.K,
		Alpha:  ws.Alpha,
		Params: &porsw.Params{S: ws.S, L: ws.L, P: ws.P},
	}
	return NewChallenger(sk, s), nil
}

// ---------------------------------------------------------------------------
// ProverFactory
// ---------------------------------------------------------------------------

type proverFactory struct{}

// NewProverFactory returns a ProverFactory that builds an SW Prover from
// the setup payload produced by Tagger.ProverSetup.
func NewProverFactory() line.ProverFactory { return proverFactory{} }

func (proverFactory) NewProver(setup []byte, _ blocks.BlockStore) (line.Prover, error) {
	var ws wireSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("sw.NewProver: %w", err)
	}
	return NewProverFromWire(ws.S, ws.L, ws.P, ws.Tags)
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger implements line.Challenger for the SW private-key scheme.
type Challenger struct {
	sk *porsw.SecretKey
	s  *suite.Suite
}

func NewChallenger(sk *porsw.SecretKey, s *suite.Suite) *Challenger {
	return &Challenger{sk: sk, s: s}
}

// DetectionProbability returns the probability that a single challenge catches
// a server that has corrupted corruptFraction of n blocks.
func (ch *Challenger) DetectionProbability(n int, corruptFraction float64) float64 {
	return confidence.HypergeometricDetection(n, ch.sk.Params.L, corruptFraction)
}

// ChalBytes returns the binary size of a compact seed challenge: 1+32+4+4 = 41 bytes.
func (ch *Challenger) ChalBytes(_ line.Challenge) int {
	return 41
}

func (ch *Challenger) Challenge(ids [][]byte) (line.Challenge, line.Validator, error) {
	c := ch.sk.Params.L
	if c > len(ids) {
		c = len(ids)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("sw.Challenge: seed: %w", err)
	}
	b, err := json.Marshal(wireChal{SuiteID: ch.s.ID(), Seed: seed, C: c, N: len(ids)})
	if err != nil {
		return nil, nil, fmt.Errorf("sw.Challenge: marshal: %w", err)
	}
	idsCopy := make([][]byte, len(ids))
	copy(idsCopy, ids)
	return line.Challenge(b), NewValidator(ch.sk, idsCopy), nil
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

// Prover implements line.Prover for the SW private-key scheme.
type Prover struct {
	params *porsw.Params
	tags   []*porsw.Tag
}

// NewProverFromWire builds a server-side Prover from primitive wire values,
// avoiding the need to import por/sw directly.
func NewProverFromWire(s, l int, p *big.Int, tags []line.Tag) (*Prover, error) {
	return NewProver(&porsw.Params{S: s, L: l, P: p}, tags)
}

// NewProver constructs a Prover from opaque tags returned by Tagger.TagBlocks.
func NewProver(params *porsw.Params, tags []line.Tag) (*Prover, error) {
	decoded := make([]*porsw.Tag, len(tags))
	for i, t := range tags {
		var wt wireTag
		if err := json.Unmarshal(t, &wt); err != nil {
			return nil, fmt.Errorf("sw.NewProver: tag %d: %w", i, err)
		}
		decoded[i] = &porsw.Tag{Sigma: wt.Sigma}
	}
	return &Prover{params: params, tags: decoded}, nil
}

// ProofBytes returns the binary size of a proof: sigma plus each mu value.
func (p *Prover) ProofBytes(proof line.Proof) int {
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return len(proof)
	}
	n := len(wp.Sigma.Bytes())
	for _, mu := range wp.Mu {
		n += len(mu.Bytes())
	}
	return n
}

// Prove implements line.Prover. store is 0-indexed.
func (p *Prover) Prove(chal line.Challenge, store blocks.BlockStore) (line.Proof, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return nil, fmt.Errorf("sw.Prove: challenge: %w", err)
	}
	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return nil, fmt.Errorf("sw.Prove: unknown suite %d", wc.SuiteID)
	}
	ids := store.IDs()
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, ids, wc.C, p.params.P)

	proof, err := porsw.RespondFetch(p.params, p.tags,
		&porsw.Challenge{Indices: indices, Coeffs: coeffs},
		store,
	)
	if err != nil {
		return nil, fmt.Errorf("sw.Prove: %w", err)
	}

	b, err := json.Marshal(wireProof{Sigma: proof.Sigma, Mu: proof.Mu})
	if err != nil {
		return nil, fmt.Errorf("sw.Prove: marshal: %w", err)
	}
	return line.Proof(b), nil
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

// Validator implements line.Validator for the SW private-key scheme.
// ids are the block identifiers from the store at challenge time, used to
// re-derive the same indices and coefficients as the prover per §3.2.
type Validator struct {
	sk  *porsw.SecretKey
	ids [][]byte
}

func NewValidator(sk *porsw.SecretKey, ids [][]byte) *Validator {
	return &Validator{sk: sk, ids: ids}
}

func (v *Validator) Verify(chal line.Challenge, proof line.Proof) (bool, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return false, fmt.Errorf("sw.Verify: challenge: %w", err)
	}
	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return false, fmt.Errorf("sw.Verify: unknown suite %d", wc.SuiteID)
	}
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, v.ids, wc.C, v.sk.Params.P)
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return false, fmt.Errorf("sw.Verify: proof: %w", err)
	}
	return porsw.Verify(s, v.sk, v.ids,
		&porsw.Challenge{Indices: indices, Coeffs: coeffs},
		&porsw.Proof{Sigma: wp.Sigma, Mu: wp.Mu},
	)
}
