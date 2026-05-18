// Package erway wires the DPDP I math (pdp/erway) to the protocol interfaces.
// Challenges and proofs are JSON-encoded byte slices.
//
// The erway Tagger holds the server-side SkipList in memory after TagBlocks;
// serialization of the SkipList is a planned follow-up.
package erway

import (
	"encoding/json"
	"fmt"
	"math/big"

	pdperway "github.com/pinionengineering/storage-proofs/pdp/erway"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/confidence"
	"github.com/pinionengineering/storage-proofs/line"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

// ---------------------------------------------------------------------------
// Wire types (JSON, provisional)
// ---------------------------------------------------------------------------

type wireChal struct {
	SuiteID uint8      `json:"suite_id"`
	Indices []int      `json:"indices"`
	Coeffs  []*big.Int `json:"coeffs"`
	N       int        `json:"n"`
}

type wireProofStep struct {
	Level    int    `json:"level"`
	Rank     int    `json:"rank"`
	Right    bool   `json:"right"`
	SibLabel []byte `json:"sib_label"`
	Q        int    `json:"q"`
}

type wireBlockProof struct {
	Tag   []byte          `json:"tag"`
	Steps []wireProofStep `json:"steps"`
}

type wireProof struct {
	Blocks []wireBlockProof `json:"blocks"`
	M      *big.Int         `json:"m"`
}

func encodeProof(p *pdperway.Proof) (line.Proof, error) {
	wp := wireProof{
		Blocks: make([]wireBlockProof, len(p.Blocks)),
		M:      p.M,
	}
	for i, bp := range p.Blocks {
		steps := make([]wireProofStep, len(bp.Steps))
		for j, st := range bp.Steps {
			steps[j] = wireProofStep{
				Level:    st.Level,
				Rank:     st.Rank,
				Right:    st.Right,
				SibLabel: st.SibLabel,
				Q:        st.Q,
			}
		}
		wp.Blocks[i] = wireBlockProof{Tag: bp.Tag, Steps: steps}
	}
	b, err := json.Marshal(wp)
	return line.Proof(b), err
}

func decodeProof(b line.Proof) (*pdperway.Proof, error) {
	var wp wireProof
	if err := json.Unmarshal(b, &wp); err != nil {
		return nil, err
	}
	p := &pdperway.Proof{
		Blocks: make([]pdperway.BlockProof, len(wp.Blocks)),
		M:      wp.M,
	}
	for i, wb := range wp.Blocks {
		steps := make([]pdperway.ProofStep, len(wb.Steps))
		for j, st := range wb.Steps {
			steps[j] = pdperway.ProofStep{
				Level:    st.Level,
				Rank:     st.Rank,
				Right:    st.Right,
				SibLabel: st.SibLabel,
				Q:        st.Q,
			}
		}
		p.Blocks[i] = pdperway.BlockProof{Tag: wb.Tag, Steps: steps}
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// Tagger
// ---------------------------------------------------------------------------

// Tagger implements line.Tagger for the DPDP I scheme. After TagBlocks,
// the SkipList and Basis are available via their respective methods.
type Tagger struct {
	pk    *pdp.PublicKey
	s     *suite.Suite
	store blocks.BlockStore   // cached after TagBlocks
	sl    *pdperway.SkipList  // set after TagBlocks
	basis pdperway.Basis      // set after TagBlocks
}

func NewTagger(pk *pdp.PublicKey, s *suite.Suite) *Tagger {
	return &Tagger{pk: pk, s: s}
}

// TagBlocks builds the authenticated skip list and returns per-block RSA hash
// tags (T(b) = g^H(b) mod N). The SkipList and Basis are also retained for
// use by NewProver and NewValidator respectively.
func (t *Tagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	sl, basis, err := pdperway.Build(t.s, t.pk, store)
	if err != nil {
		return nil, fmt.Errorf("erway.TagBlocks: %w", err)
	}
	t.store = store
	t.sl = sl
	t.basis = basis

	n := store.Len()
	tags := make([]line.Tag, n)
	for i := range n {
		block, err := store.Block(i)
		if err != nil {
			return nil, fmt.Errorf("erway.TagBlocks[%d]: %w", i, err)
		}
		tagVal := pdperway.BlockTag(t.s, t.pk, block)
		b, err := json.Marshal(tagVal)
		if err != nil {
			return nil, fmt.Errorf("erway.TagBlocks[%d]: %w", i, err)
		}
		tags[i] = line.Tag(b)
	}
	return tags, nil
}

// SkipList returns the server-side authenticated skip list built by TagBlocks.
func (t *Tagger) SkipList() *pdperway.SkipList { return t.sl }

// Basis returns the client-side O(1) verification state built by TagBlocks.
func (t *Tagger) Basis() []byte { return []byte(t.basis) }

// ---------------------------------------------------------------------------
// SetupProducer (Tagger implements line.SetupProducer)
// ---------------------------------------------------------------------------

type wireSetup struct {
	Protocol string   `json:"protocol"`
	PKN      *big.Int `json:"pk_n"`
	PKG      *big.Int `json:"pk_g"`
	Heights  []int    `json:"heights"` // per-block tower heights, sent per §3.4 of the paper
}

type wireClientSetup struct {
	Protocol string   `json:"protocol"`
	SuiteID  uint8    `json:"suite_id"`
	PKN      *big.Int `json:"pk_n"`
	PKG      *big.Int `json:"pk_g"`
	Basis    []byte   `json:"basis"`
}

func (t *Tagger) ProverSetup() ([]byte, error) {
	return json.Marshal(wireSetup{Protocol: "erway", PKN: t.pk.N, PKG: t.pk.G, Heights: t.sl.Heights()})
}

func (t *Tagger) ClientSetup() ([]byte, error) {
	return json.Marshal(wireClientSetup{
		Protocol: "erway",
		SuiteID:  t.s.ID(),
		PKN:      t.pk.N, PKG: t.pk.G,
		Basis: t.basis,
	})
}

func (t *Tagger) EncodedBlocks() blocks.BlockStore { return t.store }

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory that reconstructs an
// erway Challenger from a blob produced by Tagger.ClientSetup.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, c int) (line.Challenger, error) {
	var ws wireClientSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("erway.NewChallenger: %w", err)
	}
	s, ok := suite.SuiteByID(ws.SuiteID)
	if !ok {
		return nil, fmt.Errorf("erway.NewChallenger: unknown suite %d", ws.SuiteID)
	}
	return NewChallenger(s, c, &pdp.PublicKey{N: ws.PKN, G: ws.PKG}, ws.Basis), nil
}

// ---------------------------------------------------------------------------
// ProverFactory
// ---------------------------------------------------------------------------

type proverFactory struct {
	s *suite.Suite
}

// NewProverFactory returns a ProverFactory that builds an erway Prover from
// the setup payload produced by Tagger.ProverSetup.
func NewProverFactory(s *suite.Suite) line.ProverFactory { return proverFactory{s: s} }

func (f proverFactory) NewProver(setup []byte, store blocks.BlockStore) (line.Prover, error) {
	var ws wireSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("erway.NewProver: %w", err)
	}
	pk := &pdp.PublicKey{N: ws.PKN, G: ws.PKG}
	sl, _, err := pdperway.BuildWithHeights(f.s, pk, store, ws.Heights)
	if err != nil {
		return nil, fmt.Errorf("erway.NewProver: %w", err)
	}
	return &Prover{pk: pk, sl: sl}, nil
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger implements line.Challenger for the DPDP I scheme.
type Challenger struct {
	suiteID uint8
	c       int // blocks per challenge
	pk      *pdp.PublicKey
	basis   pdperway.Basis
}

func NewChallenger(s *suite.Suite, c int, pk *pdp.PublicKey, basis []byte) *Challenger {
	return &Challenger{suiteID: s.ID(), c: c, pk: pk, basis: pdperway.Basis(basis)}
}

// DetectionProbability returns the probability that a single challenge catches
// a server that has corrupted corruptFraction of n blocks.
func (ch *Challenger) DetectionProbability(n int, corruptFraction float64) float64 {
	return confidence.HypergeometricDetection(n, ch.c, corruptFraction)
}

func (ch *Challenger) Challenge(numBlocks int) (line.Challenge, line.Validator, error) {
	count := ch.c
	if count > numBlocks {
		count = numBlocks
	}
	chal, err := pdperway.MakeChallenge(numBlocks, count)
	if err != nil {
		return nil, nil, fmt.Errorf("erway.Challenge: %w", err)
	}
	b, err := json.Marshal(wireChal{
		SuiteID: ch.suiteID,
		Indices: chal.Indices,
		Coeffs:  chal.Coeffs,
		N:       chal.N,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("erway.Challenge: marshal: %w", err)
	}
	return line.Challenge(b), NewValidator(ch.pk, ch.basis), nil
}

// ChalBytes returns the binary size of a challenge: header plus C*(index+coeff).
func (ch *Challenger) ChalBytes(chal line.Challenge) int {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return len(chal)
	}
	// SuiteID(1) + N(4) + C×index(4)
	n := 5 + 4*len(wc.Indices)
	for _, c := range wc.Coeffs {
		n += len(c.Bytes())
	}
	return n
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

// Prover implements line.Prover for the DPDP I scheme.
type Prover struct {
	pk *pdp.PublicKey
	sl *pdperway.SkipList
}

// NewProver constructs a Prover from a SkipList already in memory (e.g. from Tagger.SkipList()).
func NewProver(pk *pdp.PublicKey, sl *pdperway.SkipList) *Prover {
	return &Prover{pk: pk, sl: sl}
}

// NewProverFromBlocks builds the authenticated skip list from a block store and
// returns a ready Prover. Use this when the server has the file but no
// pre-built SkipList (e.g. erway setup, where only the public key is uploaded).
func NewProverFromBlocks(s *suite.Suite, pk *pdp.PublicKey, store blocks.BlockStore) (*Prover, error) {
	sl, _, err := pdperway.Build(s, pk, store)
	if err != nil {
		return nil, fmt.Errorf("erway.NewProverFromBlocks: %w", err)
	}
	return &Prover{pk: pk, sl: sl}, nil
}

// ProofBytes returns the binary size of a proof: per-block tag and path steps
// plus the accumulated M value.
func (p *Prover) ProofBytes(proof line.Proof) int {
	pp, err := decodeProof(proof)
	if err != nil {
		return len(proof)
	}
	n := len(pp.M.Bytes())
	for _, bp := range pp.Blocks {
		n += len(bp.Tag)
		for _, step := range bp.Steps {
			// Level(4) + Rank(4) + Right(1) + SibLabel + Q(4)
			n += 9 + len(step.SibLabel)
		}
	}
	return n
}

// Prove implements line.Prover. store is 0-indexed; erway uses 1-indexed
// internally, so pdperway.Prove handles the translation via store.Block(idx-1).
func (p *Prover) Prove(chal line.Challenge, store blocks.BlockStore) (line.Proof, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return nil, fmt.Errorf("erway.Prove: challenge: %w", err)
	}

	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return nil, fmt.Errorf("erway.Prove: unknown suite %d", wc.SuiteID)
	}

	proof, err := pdperway.Prove(s, p.pk, p.sl,
		&pdperway.Challenge{Indices: wc.Indices, Coeffs: wc.Coeffs, N: wc.N},
		store,
	)
	if err != nil {
		return nil, fmt.Errorf("erway.Prove: %w", err)
	}
	return encodeProof(proof)
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

// Validator implements line.Validator for the DPDP I scheme.
type Validator struct {
	pk    *pdp.PublicKey
	basis pdperway.Basis
}

// NewValidator constructs a Validator from the public key and the basis
// returned by Tagger.Basis().
func NewValidator(pk *pdp.PublicKey, basis []byte) *Validator {
	return &Validator{pk: pk, basis: pdperway.Basis(basis)}
}

func (v *Validator) Verify(chal line.Challenge, proof line.Proof) (bool, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return false, fmt.Errorf("erway.Verify: challenge: %w", err)
	}
	p, err := decodeProof(proof)
	if err != nil {
		return false, fmt.Errorf("erway.Verify: proof: %w", err)
	}
	return pdperway.VerifyProof(v.pk,
		v.basis,
		&pdperway.Challenge{Indices: wc.Indices, Coeffs: wc.Coeffs, N: wc.N},
		p,
	)
}
