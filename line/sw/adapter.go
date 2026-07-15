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
	sk       *porsw.SecretKey
	s        *suite.Suite
	store    blocks.BlockStore // cached after TagBlocks
	tags     []line.Tag        // cached after TagBlocks
	ids      [][]byte          // store.IDs() captured at TagBlocks time
	blockLen int               // byte length of first block, for extraction
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
	t.ids = store.IDs()
	if store.Len() > 0 {
		b, err := blocks.BlockAt(store, 0)
		if err != nil {
			return nil, fmt.Errorf("sw.TagBlocks: first block: %w", err)
		}
		t.blockLen = len(b)
	}
	return tags, nil
}

// ---------------------------------------------------------------------------
// SetupProducer (Tagger implements line.SetupProducer)
// ---------------------------------------------------------------------------

type wireSetup struct {
	Protocol string     `json:"protocol"`
	S        int        `json:"sw_s"`
	P        *big.Int   `json:"sw_p"`
	Tags     []line.Tag `json:"tags"`
}

type wireClientSetup struct {
	Protocol string     `json:"protocol"`
	SuiteID  uint8      `json:"suite_id"`
	K        []byte     `json:"sk_k"`
	Alpha    []*big.Int `json:"sk_alpha"`
	S        int        `json:"params_s"`
	P        *big.Int   `json:"params_p"`
}

func (t *Tagger) ProverSetup() ([]byte, error) {
	p := t.sk.Params
	return json.Marshal(wireSetup{Protocol: "sw", S: p.S, P: p.P, Tags: t.tags})
}

func (t *Tagger) ClientSetup() ([]byte, error) {
	p := t.sk.Params
	return json.Marshal(wireClientSetup{
		Protocol: "sw",
		SuiteID:  t.s.ID(),
		K:        t.sk.K,
		Alpha:    t.sk.Alpha,
		S:        p.S, P: p.P,
	})
}

func (t *Tagger) EncodedBlocks() blocks.BlockStore { return t.store }

// SecretKey returns the underlying SecretKey for key serialization.
// Used by the capability layer to marshal/unmarshal the full key for GCS storage.
func (t *Tagger) SecretKey() *porsw.SecretKey { return t.sk }

// NewExtractor implements line.ExtractorProducer. Must be called after TagBlocks.
// The extractor accumulates witnessed (challenge, proof) pairs; once it has
// enough linearly independent equations it can recover the original file blocks.
func (t *Tagger) NewExtractor() (line.Extractor, error) {
	if t.ids == nil {
		return nil, fmt.Errorf("sw: TagBlocks must be called before NewExtractor")
	}
	N := len(t.ids)
	ids := make([][]byte, N)
	copy(ids, t.ids)
	return &swExtractor{
		s:        t.s,
		sk:       t.sk,
		ids:      ids,
		blockLen: t.blockLen,
		rows:     nil,
	}, nil
}

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory that reconstructs an sw
// Challenger from a blob produced by Tagger.ClientSetup. c is the number of
// blocks to sample per challenge, chosen fresh by the caller each time a
// Challenger is built — it is not stored key material.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, c int) (line.Challenger, error) {
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
		Params: &porsw.Params{S: ws.S, P: ws.P},
	}
	return NewChallenger(sk, s, c), nil
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
	return NewProverFromWire(ws.S, ws.P, ws.Tags)
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger implements line.Challenger for the SW private-key scheme.
type Challenger struct {
	sk *porsw.SecretKey
	s  *suite.Suite
	c  int // blocks sampled per challenge
}

func NewChallenger(sk *porsw.SecretKey, s *suite.Suite, c int) *Challenger {
	return &Challenger{sk: sk, s: s, c: c}
}

// DetectionProbability returns the probability that a single challenge catches
// a server that has corrupted corruptFraction of n blocks.
func (ch *Challenger) DetectionProbability(n int, corruptFraction float64) float64 {
	return confidence.HypergeometricDetection(n, ch.c, corruptFraction)
}

// ChalBytes returns the binary size of a compact seed challenge: 1+32+4+4 = 41 bytes.
func (ch *Challenger) ChalBytes(_ line.Challenge) int {
	return 41
}

func (ch *Challenger) Challenge(ids [][]byte) (line.Challenge, line.Validator, error) {
	c := ch.c
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
func NewProverFromWire(s int, p *big.Int, tags []line.Tag) (*Prover, error) {
	return NewProver(&porsw.Params{S: s, P: p}, tags)
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

// ---------------------------------------------------------------------------
// Extractor
// ---------------------------------------------------------------------------

// swRow records the information from one witnessed (challenge, proof) pair.
// Each row contributes one linear equation per sector: the challenged block
// positions and their ν coefficients form the LHS; the proof's μ values are
// the per-sector RHS.
type swRow struct {
	indices []int      // positions in ids that were challenged
	coeffs  []*big.Int // ν_t values, parallel to indices
	rhs     []*big.Int // μ_j values, one per sector (length S)
}

// swExtractor implements line.Extractor for the SW private-key scheme.
// It accumulates witnessed proofs as linear equations and solves for the
// original block sector values once the system becomes full-rank.
type swExtractor struct {
	s        *suite.Suite
	sk       *porsw.SecretKey
	ids      [][]byte // block identifiers captured at TagBlocks time
	blockLen int      // byte length of each original block
	rows     []swRow
}

// Witness records one validated (challenge, proof) pair. The caller must
// verify the proof before calling Witness.
func (e *swExtractor) Witness(chal line.Challenge, proof line.Proof) error {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return fmt.Errorf("sw.Extractor.Witness: challenge: %w", err)
	}
	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return fmt.Errorf("sw.Extractor.Witness: unknown suite %d", wc.SuiteID)
	}
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return fmt.Errorf("sw.Extractor.Witness: proof: %w", err)
	}
	if len(wp.Mu) != e.sk.Params.S {
		return fmt.Errorf("sw.Extractor.Witness: proof has %d μ values, want %d", len(wp.Mu), e.sk.Params.S)
	}
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, e.ids, wc.C, e.sk.Params.P)
	e.rows = append(e.rows, swRow{indices: indices, coeffs: coeffs, rhs: wp.Mu})
	return nil
}

// Extract solves for the original block values from the accumulated witnessed
// proofs. Returns ErrInsufficientProofs if the system is not yet full-rank.
//
// The extraction property of SW (§3) requires P > max(sector value), which
// ensures that the mod-P representation of each sector is lossless and the
// recovered bytes exactly reproduce the originals.
func (e *swExtractor) Extract() (blocks.BlockStore, error) {
	N := len(e.ids)
	S := e.sk.Params.S
	P := e.sk.Params.P
	if N == 0 {
		return blocks.NewMemStore(nil), nil
	}

	// Build one augmented matrix per sector and solve each independently.
	// Each row has N coefficient entries plus a RHS; the coefficient for
	// block position p is ν_t when p == indices[t], zero otherwise.
	sectorVals := make([][]*big.Int, N) // sectorVals[i][j] = f_{i,j}
	for i := range N {
		sectorVals[i] = make([]*big.Int, S)
	}

	aug := make([][]*big.Int, len(e.rows))
	for r, row := range e.rows {
		aug[r] = make([]*big.Int, N+1)
		for k := range aug[r] {
			aug[r][k] = new(big.Int)
		}
		for k, idx := range row.indices {
			aug[r][idx] = new(big.Int).Set(row.coeffs[k])
		}
	}

	for j := range S {
		// Set the RHS column for sector j.
		for r, row := range e.rows {
			aug[r][N] = new(big.Int).Set(row.rhs[j])
		}
		sol := line.GaussElimModP(aug, N, P)
		if sol == nil {
			return nil, line.ErrInsufficientProofs
		}
		for i := range N {
			sectorVals[i][j] = sol[i]
		}
	}

	// Reconstruct block bytes from sector field elements.
	// sectorElem encodes sector j as block[j*sectorSize : min((j+1)*sectorSize, blockLen)]
	// interpreted as a big-endian integer mod P, so reconstruction is the inverse.
	sectorSize := (e.blockLen + S - 1) / S
	reconstructed := make([][]byte, N)
	for i := range N {
		block := make([]byte, e.blockLen)
		for j := range S {
			start := j * sectorSize
			if start >= e.blockLen {
				// Sector entirely beyond block content (S > blockLen/sectorSize can
				// happen, e.g. a block shorter than S bytes) — sectorElem returns 0
				// for these at tag time, and block[] is already zero-initialized.
				continue
			}
			end := start + sectorSize
			if end > e.blockLen {
				end = e.blockLen
			}
			size := end - start
			b := sectorVals[i][j].Bytes()
			if len(b) > size {
				b = b[len(b)-size:] // truncate leading bytes (P constraint ensures no data loss)
			}
			copy(block[end-len(b):end], b)
		}
		reconstructed[i] = block
	}
	return blocks.NewMemStore(reconstructed), nil
}
