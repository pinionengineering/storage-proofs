// Package swpub wires the Shacham-Waters public-key POR (§3.3) to the line
// protocol interfaces. Challenges and proofs are JSON-encoded byte slices.
//
// Unlike the private-key variant (line/sw), any party holding the public key
// can verify proofs. Verification uses two BN254 Ate pairings, which is
// significantly slower than the Z_p arithmetic in the private-key scheme.
package swpub

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

// bn254Order is the BN254 group order, used as the modulus for scalar arithmetic.
var bn254Order = fr.Modulus()

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
	for j := range pk.U {
		raw := pk.U[j].RawBytes()
		u[j] = raw[:]
	}
	vRaw := pk.V.RawBytes()
	return json.Marshal(wireClientSetup{
		Protocol: "swpub",
		SuiteID:  t.s.ID(),
		S:        t.ps.S(),
		Name:     pk.Name,
		V:        vRaw[:],
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

// PubScheme returns the underlying PubScheme for key serialization.
// Used by the capability layer to marshal/unmarshal the full key for GCS storage.
func (t *Tagger) PubScheme() *porsw.PubScheme { return t.ps }

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory for the SW-Pub scheme.
// c is the number of blocks to sample per challenge, chosen fresh by the
// caller each time a Challenger is built — it is not stored key material.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, c int) (line.Challenger, error) {
	var ws wireClientSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("swpub.NewChallenger: %w", err)
	}
	s, ok := suite.SuiteByID(ws.SuiteID)
	if !ok {
		return nil, fmt.Errorf("swpub.NewChallenger: unknown suite %d", ws.SuiteID)
	}
	var v bn254.G2Affine
	if _, err := v.SetBytes(ws.V); err != nil {
		return nil, fmt.Errorf("swpub.NewChallenger: V: %w", err)
	}
	u := make([]bn254.G1Affine, len(ws.U))
	for j, raw := range ws.U {
		if _, err := u[j].SetBytes(raw); err != nil {
			return nil, fmt.Errorf("swpub.NewChallenger: U[%d]: %w", j, err)
		}
	}
	pk := &porsw.PubPublicKey{Name: ws.Name, V: v, U: u}
	return &Challenger{pk: pk, suite: s, s: ws.S, c: c}, nil
}

// ---------------------------------------------------------------------------
// ProverFactory
// ---------------------------------------------------------------------------

type proverFactory struct{}

var _ line.SparseProverFactory = proverFactory{}

// NewProverFactory returns a ProverFactory (also usable as a
// SparseProverFactory) for the SW-Pub scheme.
func NewProverFactory() line.SparseProverFactory { return proverFactory{} }

func (proverFactory) NewProver(setup []byte, _ blocks.BlockStore) (line.Prover, error) {
	var ws wireProverSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("swpub.NewProver: %w", err)
	}
	m := make(line.TagMap, len(ws.Tags))
	for i, t := range ws.Tags {
		m[i] = t
	}
	return &Prover{s: ws.S, tags: m}, nil
}

// NewProverFromTagStore implements line.SparseProverFactory: builds a
// Prover that fetches tags on demand from tags, instead of requiring the
// full dense tag list NewProver does. setup's Tags field, if any, is
// ignored — only S is read (a caller that wants a smaller setup blob than
// ProverSetup produces can omit Tags entirely).
func (proverFactory) NewProverFromTagStore(setup []byte, tags line.TagStore) (line.Prover, error) {
	var ws wireProverSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("swpub.NewProverFromTagStore: %w", err)
	}
	return &Prover{s: ws.S, tags: tags}, nil
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger implements line.Challenger for the SW public-key scheme.
type Challenger struct {
	pk    *porsw.PubPublicKey
	suite *suite.Suite
	s     int
	c     int // blocks sampled per challenge
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
		return nil, nil, fmt.Errorf("swpub.Challenge: seed: %w", err)
	}
	b, err := json.Marshal(wireChal{SuiteID: ch.suite.ID(), Seed: seed, C: c, N: len(ids)})
	if err != nil {
		return nil, nil, fmt.Errorf("swpub.Challenge: marshal: %w", err)
	}
	idsCopy := make([][]byte, len(ids))
	copy(idsCopy, ids)
	return line.Challenge(b), &Validator{pk: ch.pk, ids: idsCopy}, nil
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

// Prover implements line.Prover for the SW public-key scheme. tags is a
// line.TagStore rather than a decoded, dense array — Prove fetches tags on
// demand for exactly the indices its challenge derivation selects, whether
// tags is backed by an in-memory line.TagMap (NewProver's dense
// construction) or a real targeted-read store (NewProverFromTagStore).
type Prover struct {
	s    int
	tags line.TagStore // block index -> 64-byte G1 marshal
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
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, store.IDs(), wc.C, bn254Order)
	swChal := &porsw.SWChallenge{Kind: porsw.PubKind, Indices: indices, Coeffs: coeffs}

	// Fetch tags for exactly the derived indices — the only ones
	// RespondFetch below will touch. p.tags is a line.TagStore, so for a
	// sparse construction this is where the targeted range read happens;
	// for a dense construction (line.TagMap) it's an in-memory lookup.
	sparseTags := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		t, err := p.tags.Tag(idx)
		if err != nil {
			return nil, fmt.Errorf("swpub.Prove: tag %d: %w", idx, err)
		}
		sparseTags[idx] = []byte(t)
	}

	// RespondFetch only reads ps.s from the scheme; no keypair needed.
	resp, err := porsw.NewPubSchemeFromKey(nil, p.s).RespondFetch(sparseTags, swChal, store)
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
// ids are the block identifiers from the store at challenge time, used to
// re-derive the same indices and coefficients as the prover per §3.3.
type Validator struct {
	pk  *porsw.PubPublicKey
	ids [][]byte
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
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, v.ids, wc.C, bn254Order)
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return false, fmt.Errorf("swpub.Verify: proof: %w", err)
	}
	mu := make([]*big.Int, len(wp.Mu))
	for j, m := range wp.Mu {
		mu[j] = fixed32ToBig(m)
	}
	swChal := &porsw.SWChallenge{Kind: porsw.PubKind, Indices: indices, Coeffs: coeffs}
	return porsw.VerifyPub(v.pk, swChal, &porsw.SWProof{Sigma: wp.Sigma, Mu: mu}, v.ids)
}

// ---------------------------------------------------------------------------
// Extractor
// ---------------------------------------------------------------------------

// NewExtractor implements line.ExtractorProducer. Must be called after TagBlocks.
func (t *Tagger) NewExtractor() (line.Extractor, error) {
	if t.store == nil {
		return nil, fmt.Errorf("swpub: TagBlocks must be called before NewExtractor")
	}
	blockLen := 0
	if b, err := blocks.BlockAt(t.store, 0); err == nil {
		blockLen = len(b)
	}
	return &swPubExtractor{
		S:        t.ps.S(),
		ids:      t.store.IDs(),
		blockLen: blockLen,
	}, nil
}

// swPubRow records one witnessed (challenge, proof) pair as linear equations.
// Each row contributes one equation per sector: challenged block positions and
// their ν coefficients form the LHS; the proof's μ values are the per-sector RHS.
type swPubRow struct {
	indices []int
	coeffs  []*big.Int
	rhs     []*big.Int // μ_j values, one per sector
}

// swPubExtractor implements line.Extractor for the SW public-key scheme.
// Extraction uses the same Gaussian elimination as the private-key scheme;
// the only difference is that the modulus is bn254Order instead of swP, since
// sector elements in the public scheme are reduced mod the curve order.
type swPubExtractor struct {
	S        int
	ids      [][]byte
	blockLen int
	rows     []swPubRow
}

func (e *swPubExtractor) Witness(chal line.Challenge, proof line.Proof) error {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return fmt.Errorf("swpub.Extractor.Witness: challenge: %w", err)
	}
	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return fmt.Errorf("swpub.Extractor.Witness: unknown suite %d", wc.SuiteID)
	}
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return fmt.Errorf("swpub.Extractor.Witness: proof: %w", err)
	}
	if len(wp.Mu) != e.S {
		return fmt.Errorf("swpub.Extractor.Witness: proof has %d μ values, want %d", len(wp.Mu), e.S)
	}
	indices, coeffs := line.DeriveChallenge(s, wc.Seed, e.ids, wc.C, bn254Order)
	rhs := make([]*big.Int, e.S)
	for j, m := range wp.Mu {
		rhs[j] = fixed32ToBig(m)
	}
	e.rows = append(e.rows, swPubRow{indices: indices, coeffs: coeffs, rhs: rhs})
	return nil
}

// Extract solves for the original block values once the system is full-rank.
// Returns ErrInsufficientProofs if more witnesses are needed.
func (e *swPubExtractor) Extract() (blocks.BlockStore, error) {
	N := len(e.ids)
	S := e.S
	P := bn254Order
	if N == 0 {
		return blocks.NewMemStore(nil), nil
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

	sectorVals := make([][]*big.Int, N)
	for i := range N {
		sectorVals[i] = make([]*big.Int, S)
	}
	for j := range S {
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

	sectorSize := (e.blockLen + S - 1) / S
	reconstructed := make([][]byte, N)
	for i := range N {
		block := make([]byte, e.blockLen)
		for j := range S {
			start := j * sectorSize
			if start >= e.blockLen {
				// Sector entirely beyond block content (S > blockLen/sectorSize can
				// happen, e.g. a block shorter than S bytes) — pubSectorElem returns 0
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
				b = b[len(b)-size:]
			}
			copy(block[end-len(b):end], b)
		}
		reconstructed[i] = block
	}
	return blocks.NewMemStore(reconstructed), nil
}
