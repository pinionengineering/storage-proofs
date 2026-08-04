// Package ateniese wires the S-PDP math (pdp/ateniese) to the protocol
// interfaces. Challenges and proofs are JSON-encoded byte slices.
package ateniese

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	pdpateniese "github.com/pinionengineering/storage-proofs/pdp/ateniese"
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
	N       int      `json:"n"`
	SuiteID uint8    `json:"suite_id"`
	C       int      `json:"c"`
	K1      []byte   `json:"k1"`
	K2      []byte   `json:"k2"`
	Gs      *big.Int `json:"gs"`
}

type wireTag struct {
	SuiteID uint8    `json:"suite_id"`
	T       *big.Int `json:"t"`
}

type wireProof struct {
	T   *big.Int `json:"t"`
	Rho []byte   `json:"rho"`
}

func encodeTag(tag *pdpateniese.Tag) (line.Tag, error) {
	b, err := json.Marshal(wireTag{SuiteID: tag.SuiteID, T: tag.T})
	return line.Tag(b), err
}

func decodeTag(b line.Tag) (*pdpateniese.Tag, error) {
	var wt wireTag
	if err := json.Unmarshal(b, &wt); err != nil {
		return nil, err
	}
	return &pdpateniese.Tag{SuiteID: wt.SuiteID, T: wt.T}, nil
}

// ---------------------------------------------------------------------------
// Tagger
// ---------------------------------------------------------------------------

// Tagger implements line.Tagger and line.SetupProducer for the S-PDP scheme.
type Tagger struct {
	pk         *pdp.PublicKey
	sk         *pdpateniese.SecretKey
	s          *suite.Suite
	store      blocks.BlockStore  // set after TagBlocks
	cachedTags []*pdpateniese.Tag // set after TagBlocks
}

func NewTagger(pk *pdp.PublicKey, sk *pdpateniese.SecretKey, s *suite.Suite) *Tagger {
	return &Tagger{pk: pk, sk: sk, s: s}
}

func (t *Tagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	ids := store.IDs()
	n := len(ids)
	tags := make([]line.Tag, n)
	decoded := make([]*pdpateniese.Tag, n)
	for i, id := range ids {
		block, err := store.Block(id)
		if err != nil {
			return nil, fmt.Errorf("ateniese.TagBlocks[%d]: %w", i, err)
		}
		tag, err := pdpateniese.TagBlock(t.s, t.pk, t.sk, block, id)
		if err != nil {
			return nil, fmt.Errorf("ateniese.TagBlocks[%d]: %w", i, err)
		}
		b, err := encodeTag(tag)
		if err != nil {
			return nil, fmt.Errorf("ateniese.TagBlocks[%d]: encode: %w", i, err)
		}
		tags[i] = b
		decoded[i] = tag
	}
	t.store = store
	t.cachedTags = decoded
	return tags, nil
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger holds the client-side S-PDP state and implements line.Challenger.
// Each call to Challenge returns a bound Validator carrying that round's secret,
// so concurrent or pipelined audit rounds are safe.
type Challenger struct {
	pk *pdp.PublicKey
	sk *pdpateniese.SecretKey
	s  *suite.Suite
	c  int // blocks per challenge
}

// NewChallenger constructs a Challenger. c is the number of blocks to include
// in each challenge. Unlike GenProof's server side, CheckProof (via the
// Validator Challenge returns) never needs tag values, only the ids Challenge
// itself is given, so no tags are threaded through here.
func NewChallenger(pk *pdp.PublicKey, sk *pdpateniese.SecretKey, s *suite.Suite, c int) (*Challenger, error) {
	return &Challenger{pk: pk, sk: sk, s: s, c: c}, nil
}

// DetectionProbability returns the probability that a single challenge catches
// a server that has corrupted corruptFraction of n blocks.
func (c *Challenger) DetectionProbability(n int, corruptFraction float64) float64 {
	return confidence.HypergeometricDetection(n, c.c, corruptFraction)
}

// Challenge implements line.Challenger. The returned Validator is bound to
// this round's secret s and must be used to verify the proof for this challenge.
func (c *Challenger) Challenge(ids [][]byte) (line.Challenge, line.Validator, error) {
	numBlocks := len(ids)
	s, err := rand.Int(rand.Reader, c.pk.N)
	if err != nil {
		return nil, nil, fmt.Errorf("ateniese.Challenge: %w", err)
	}

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	if _, err = rand.Read(k1); err != nil {
		return nil, nil, fmt.Errorf("ateniese.Challenge: k1: %w", err)
	}
	if _, err = rand.Read(k2); err != nil {
		return nil, nil, fmt.Errorf("ateniese.Challenge: k2: %w", err)
	}

	count := c.c
	if count > numBlocks {
		count = numBlocks
	}

	b, err := json.Marshal(wireChal{
		N:       numBlocks,
		SuiteID: c.s.ID(),
		C:       count,
		K1:      k1,
		K2:      k2,
		Gs:      new(big.Int).Exp(c.pk.G, s, c.pk.N),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ateniese.Challenge: marshal: %w", err)
	}
	idsCopy := make([][]byte, len(ids))
	copy(idsCopy, ids)
	v := &roundValidator{pk: c.pk, sk: c.sk, s: c.s, ids: idsCopy, secret: s}
	return line.Challenge(b), v, nil
}

// ChalBytes returns the binary size of a challenge: fixed header fields plus
// the byte length of the Gs group element.
func (c *Challenger) ChalBytes(chal line.Challenge) int {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return len(chal)
	}
	// N(4) + SuiteID(1) + C(4) + K1 + K2 + Gs
	return 9 + len(wc.K1) + len(wc.K2) + len(wc.Gs.Bytes())
}

// ---------------------------------------------------------------------------
// roundValidator (implements Validator for one ateniese round)
// ---------------------------------------------------------------------------

// roundValidator's ids are the client's own trusted record of block
// identifiers, captured at Challenge time from that call's own ids
// parameter. CheckProof self-derives each challenged W from sk.V and ids
// (see pdp/ateniese's BlockW), so no tag values are needed here at all.
type roundValidator struct {
	pk     *pdp.PublicKey
	sk     *pdpateniese.SecretKey
	s      *suite.Suite
	ids    [][]byte
	secret *big.Int
}

func (v *roundValidator) Verify(chal line.Challenge, proof line.Proof) (bool, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return false, fmt.Errorf("ateniese.Verify: challenge: %w", err)
	}
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return false, fmt.Errorf("ateniese.Verify: proof: %w", err)
	}
	return pdpateniese.CheckProof(v.s, v.pk, v.sk, v.secret, v.ids,
		&pdpateniese.Challenge{SuiteID: wc.SuiteID, C: wc.C, K1: wc.K1, K2: wc.K2, Gs: wc.Gs},
		&pdpateniese.Proof{T: wp.T, Rho: wp.Rho},
	)
}

// ---------------------------------------------------------------------------
// SetupProducer (Tagger implements line.SetupProducer)
// ---------------------------------------------------------------------------

type wireSetup struct {
	Protocol string     `json:"protocol"`
	Tags     []line.Tag `json:"tags"`
	PKN      *big.Int   `json:"pk_n"`
	PKG      *big.Int   `json:"pk_g"`
}

// wireClientSetup carries what the client needs to reconstruct a Challenger.
// It has no Tags field: CheckProof (via Challenger's Validator) never needs
// tag values, only the ids each Challenge call is given, so the client has
// no reason to retain tags past setup, matching the paper's own step 1 (C
// deletes its local copies of the blocks and tags, keeping only pk, sk).
type wireClientSetup struct {
	Protocol string   `json:"protocol"`
	SuiteID  uint8    `json:"suite_id"`
	PKN      *big.Int `json:"pk_n"`
	PKG      *big.Int `json:"pk_g"`
	SKE      *big.Int `json:"sk_e"`
	SKD      *big.Int `json:"sk_d"`
	SKV      []byte   `json:"sk_v"`
	SKPhi    *big.Int `json:"sk_phi"`
}

func encodeTags(cached []*pdpateniese.Tag) ([]line.Tag, error) {
	tags := make([]line.Tag, len(cached))
	for i, tag := range cached {
		b, err := encodeTag(tag)
		if err != nil {
			return nil, fmt.Errorf("tag %d: %w", i, err)
		}
		tags[i] = b
	}
	return tags, nil
}

func (t *Tagger) ProverSetup() ([]byte, error) {
	tags, err := encodeTags(t.cachedTags)
	if err != nil {
		return nil, fmt.Errorf("ateniese.ProverSetup: %w", err)
	}
	return json.Marshal(wireSetup{Protocol: "ateniese", Tags: tags, PKN: t.pk.N, PKG: t.pk.G})
}

func (t *Tagger) ClientSetup() ([]byte, error) {
	return json.Marshal(wireClientSetup{
		Protocol: "ateniese",
		SuiteID:  t.s.ID(),
		PKN:      t.pk.N, PKG: t.pk.G,
		SKE: t.sk.E, SKD: t.sk.D, SKV: t.sk.V, SKPhi: t.sk.Phi,
	})
}

func (t *Tagger) EncodedBlocks() blocks.BlockStore        { return t.store }
func (t *Tagger) PublicKey() *pdp.PublicKey               { return t.pk }
func (t *Tagger) SecretKey() *pdpateniese.SecretKey       { return t.sk }

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory that reconstructs an
// ateniese Challenger from a blob produced by Tagger.ClientSetup.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, c int) (line.Challenger, error) {
	var ws wireClientSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("ateniese.NewChallenger: %w", err)
	}
	s, ok := suite.SuiteByID(ws.SuiteID)
	if !ok {
		return nil, fmt.Errorf("ateniese.NewChallenger: unknown suite %d", ws.SuiteID)
	}
	pk := &pdp.PublicKey{N: ws.PKN, G: ws.PKG}
	sk := &pdpateniese.SecretKey{E: ws.SKE, D: ws.SKD, V: ws.SKV, Phi: ws.SKPhi}
	return NewChallenger(pk, sk, s, c)
}

// ---------------------------------------------------------------------------
// ProverFactory
// ---------------------------------------------------------------------------

type proverFactory struct{}

var _ line.SparseProverFactory = proverFactory{}

// NewProverFactory returns a ProverFactory (also usable as a
// SparseProverFactory) that builds an ateniese Prover from the setup payload
// produced by Tagger.ProverSetup.
func NewProverFactory() line.SparseProverFactory { return proverFactory{} }

func (proverFactory) NewProver(setup []byte, _ blocks.BlockStore) (line.Prover, error) {
	var ws wireSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("ateniese.NewProver: %w", err)
	}
	return NewProver(&pdp.PublicKey{N: ws.PKN, G: ws.PKG}, ws.Tags)
}

// NewProverFromTagStore implements line.SparseProverFactory: builds a
// Prover that fetches tags on demand from tags, instead of requiring the
// full dense tag list NewProver does. setup's Tags field, if any, is
// ignored; only PKN/PKG are read, so a caller that wants a smaller setup
// blob than ProverSetup produces can omit Tags entirely.
//
// Unlike sw/swpub, this adapter does not derive challenge indices itself
// before calling into the math layer: pdp/ateniese.GenProof derives them
// internally via BuildPRP (§4.3 Fig. 2 step 1) and is given a TagFetcher
// closure instead, so the permutation is computed exactly once per proof,
// inside GenProof.
func (proverFactory) NewProverFromTagStore(setup []byte, tags line.TagStore) (line.Prover, error) {
	var ws wireSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("ateniese.NewProverFromTagStore: %w", err)
	}
	return &Prover{pk: &pdp.PublicKey{N: ws.PKN, G: ws.PKG}, tags: tags}, nil
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

// Prover implements line.Prover for the S-PDP scheme. tags is a
// line.TagStore rather than a decoded, dense array; Prove decodes tags on
// demand for exactly the indices GenProof's own index derivation selects,
// whether tags is backed by an in-memory line.TagMap (NewProver's dense
// construction) or a real targeted-read store (NewProverFromTagStore).
type Prover struct {
	pk   *pdp.PublicKey
	tags line.TagStore
}

// NewProver constructs a Prover from the full, dense tag list returned by
// Tagger.TagBlocks (tags[i] is block i's tag). For a construction that
// fetches tags on demand rather than holding them all, see
// NewProverFromTagStore.
func NewProver(pk *pdp.PublicKey, tags []line.Tag) (*Prover, error) {
	m := make(line.TagMap, len(tags))
	for i, t := range tags {
		m[i] = t
	}
	return &Prover{pk: pk, tags: m}, nil
}

// ProofBytes returns the binary size of a proof: byte length of T plus Rho.
func (p *Prover) ProofBytes(proof line.Proof) int {
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return len(proof)
	}
	return len(wp.T.Bytes()) + len(wp.Rho)
}

// Prove implements line.Prover.
func (p *Prover) Prove(chal line.Challenge, store blocks.BlockStore) (line.Proof, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return nil, fmt.Errorf("ateniese.Prove: challenge: %w", err)
	}

	s, ok := suite.SuiteByID(wc.SuiteID)
	if !ok {
		return nil, fmt.Errorf("ateniese.Prove: unknown suite %d", wc.SuiteID)
	}

	// GenProof calls this only for the indices its own BuildPRP derivation
	// selects. For a sparse p.tags this is where the targeted range read
	// happens; for a dense p.tags (line.TagMap) it's an in-memory lookup.
	fetchTag := func(idx int) (*pdpateniese.Tag, error) {
		t, err := p.tags.Tag(idx)
		if err != nil {
			return nil, err
		}
		return decodeTag(t)
	}

	proof, err := pdpateniese.GenProof(s, p.pk, store,
		&pdpateniese.Challenge{SuiteID: wc.SuiteID, C: wc.C, K1: wc.K1, K2: wc.K2, Gs: wc.Gs},
		fetchTag,
	)
	if err != nil {
		return nil, fmt.Errorf("ateniese.Prove: %w", err)
	}

	b, err := json.Marshal(wireProof{T: proof.T, Rho: proof.Rho})
	if err != nil {
		return nil, fmt.Errorf("ateniese.Prove: marshal: %w", err)
	}
	return line.Proof(b), nil
}
