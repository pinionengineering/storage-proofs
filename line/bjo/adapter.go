// Package bjo wires the BJO POR math (por/bjo) to the protocol interfaces.
// Challenges and proofs are JSON-encoded byte slices.
//
// BJO's setup step (Encode) transforms the input blocks via SA-ECC and
// precomputes Q sentinel ciphertexts. The encoded blocks and sentinels are
// what the server stores. TagBlocks runs Encode and returns the sentinels as
// opaque tags; the full EncodedFile (encoded blocks + sentinels + MAC) is
// accessible via EncodedFile() for constructing a Prover or Extractor.
//
// Challenges are sequential: the first call to Challenge issues sentinel j=1,
// the second j=2, etc. up to Q.
package bjo

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync/atomic"

	porbjo "github.com/pinionengineering/storage-proofs/por/bjo"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	"github.com/pinionengineering/storage-proofs/suite"
)

// WireParams is the JSON-serializable form of porbjo.Params.
// The client sends this in the setup payload so the server can build a Prover
// without importing por/bjo directly.
type WireParams struct {
	V      int      `json:"v"`
	W      int      `json:"w"`
	Q      int      `json:"q"`
	P      *big.Int `json:"p"`
	GSeed  []byte   `json:"gseed"`
	OuterN int      `json:"outer_n"`
	OuterK int      `json:"outer_k"`
	Alpha  int      `json:"alpha"`
	Delta  float64  `json:"delta"`
}

func (wp WireParams) toParams() *porbjo.Params {
	return &porbjo.Params{
		V: wp.V, W: wp.W, Q: wp.Q, P: wp.P,
		GSeed: wp.GSeed, OuterN: wp.OuterN, OuterK: wp.OuterK,
		Alpha: wp.Alpha, Delta: wp.Delta,
	}
}

// ---------------------------------------------------------------------------
// Wire types (JSON, provisional)
// ---------------------------------------------------------------------------

type wireChal struct {
	J   int    `json:"j"`
	Kjc []byte `json:"kjc"`
	U   int    `json:"u"`
}

type wireProof struct {
	Mj []byte `json:"mj"`
	Qj []byte `json:"qj"`
}

// ---------------------------------------------------------------------------
// Tagger
// ---------------------------------------------------------------------------

// Tagger implements line.Tagger for the BJO scheme. After TagBlocks, the
// EncodedFile is available via EncodedFile() for Prover and Extractor setup.
type Tagger struct {
	mk *porbjo.MasterKey
	s  *suite.Suite
	ef *porbjo.EncodedFile // set after TagBlocks
}

func NewTagger(mk *porbjo.MasterKey, s *suite.Suite) *Tagger {
	return &Tagger{mk: mk, s: s}
}

// TagBlocks encodes the blocks with SA-ECC and returns the Q precomputed
// sentinel ciphertexts as opaque tags (one per sentinel, not one per block).
func (t *Tagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	ef, err := porbjo.Encode(t.s, t.mk, store)
	if err != nil {
		return nil, fmt.Errorf("bjo.TagBlocks: %w", err)
	}
	t.ef = ef

	tags := make([]line.Tag, len(ef.Sentinels))
	for i, s := range ef.Sentinels {
		tags[i] = line.Tag(s)
	}
	return tags, nil
}

// EncodedFile returns the full encoded file produced by TagBlocks, which the
// server must store (encoded blocks + sentinels + MAC).
func (t *Tagger) EncodedFile() *porbjo.EncodedFile { return t.ef }

// NewExtractor implements line.ExtractorProducer. Must be called after TagBlocks.
func (t *Tagger) NewExtractor() (line.Extractor, error) {
	if t.ef == nil {
		return nil, fmt.Errorf("bjo: TagBlocks must be called before NewExtractor")
	}
	return NewExtractor(t.s, t.mk, t.ef), nil
}

// WireParams returns the scheme parameters in a JSON-serializable form for
// inclusion in the setup payload to the server.
func (t *Tagger) WireParams() WireParams {
	p := t.mk.Params
	return WireParams{V: p.V, W: p.W, Q: p.Q, P: p.P, GSeed: p.GSeed,
		OuterN: p.OuterN, OuterK: p.OuterK, Alpha: p.Alpha, Delta: p.Delta}
}

// Sentinels returns the Q precomputed sentinel ciphertexts for the setup payload.
func (t *Tagger) Sentinels() [][]byte { return t.ef.Sentinels }

// EncodedBlocks returns the full encoded block store (original + parity).
// The server stores these as the file it audits.
func (t *Tagger) EncodedBlocks() blocks.BlockStore    { return blocks.NewMemStore(t.ef.Blocks) }
func (t *Tagger) MasterKey() *porbjo.MasterKey        { return t.mk }

// ---------------------------------------------------------------------------
// SetupProducer (Tagger implements line.SetupProducer)
// ---------------------------------------------------------------------------

type wireSetup struct {
	Protocol  string     `json:"protocol"`
	Params    WireParams `json:"bjo_params"`
	Sentinels [][]byte   `json:"bjo_sentinels"`
}

func (t *Tagger) ProverSetup() ([]byte, error) {
	return json.Marshal(wireSetup{
		Protocol:  "bjo",
		Params:    t.WireParams(),
		Sentinels: t.Sentinels(),
	})
}

type wireClientSetup struct {
	Protocol string     `json:"protocol"`
	KChal    []byte     `json:"mk_kchal"`
	KInd     []byte     `json:"mk_kind"`
	KMACFile []byte     `json:"mk_kmacfile"`
	KEnc     []byte     `json:"mk_kenc"`
	KPerm    []byte     `json:"mk_kperm"`
	KECCPerm []byte     `json:"mk_keccperm"`
	KECCEnc  []byte     `json:"mk_keccenc"`
	Params   WireParams `json:"params"`
}

func (t *Tagger) ClientSetup() ([]byte, error) {
	mk := t.mk
	return json.Marshal(wireClientSetup{
		Protocol: "bjo",
		KChal:    mk.KChal, KInd: mk.KInd, KMACFile: mk.KMACFile,
		KEnc: mk.KEnc, KPerm: mk.KPerm, KECCPerm: mk.KECCPerm, KECCEnc: mk.KECCEnc,
		Params: t.WireParams(),
	})
}

// ---------------------------------------------------------------------------
// ChallengerFactory
// ---------------------------------------------------------------------------

type challengerFactory struct{}

// NewChallengerFactory returns a ChallengerFactory that reconstructs a BJO
// Challenger from a blob produced by Tagger.ClientSetup. c is ignored; the
// challenge count is bounded by Params.Q stored in the setup blob.
func NewChallengerFactory() line.ChallengerFactory { return challengerFactory{} }

func (challengerFactory) NewChallenger(setup []byte, _ int) (line.Challenger, error) {
	var ws wireClientSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("bjo.NewChallenger: %w", err)
	}
	mk := &porbjo.MasterKey{
		KChal:    ws.KChal, KInd: ws.KInd, KMACFile: ws.KMACFile,
		KEnc: ws.KEnc, KPerm: ws.KPerm, KECCPerm: ws.KECCPerm, KECCEnc: ws.KECCEnc,
		Params: ws.Params.toParams(),
	}
	return NewChallenger(mk), nil
}

// ---------------------------------------------------------------------------
// ProverFactory
// ---------------------------------------------------------------------------

type proverFactory struct {
	s *suite.Suite
}

// NewProverFactory returns a ProverFactory that builds a BJO Prover from
// the setup payload produced by Tagger.ProverSetup.
func NewProverFactory(s *suite.Suite) line.ProverFactory { return proverFactory{s: s} }

func (f proverFactory) NewProver(setup []byte, _ blocks.BlockStore) (line.Prover, error) {
	var ws wireSetup
	if err := json.Unmarshal(setup, &ws); err != nil {
		return nil, fmt.Errorf("bjo.NewProver: %w", err)
	}
	return NewProverFromWire(f.s, ws.Params, ws.Sentinels), nil
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

// Challenger implements line.Challenger for the BJO scheme. Sentinel
// indices are issued sequentially starting at 1; the numBlocks argument to
// Challenge is unused (BJO challenges are keyed by sentinel index, not block
// count).
type Challenger struct {
	mk   *porbjo.MasterKey
	next atomic.Int64 // next sentinel index (1-based)
}

func NewChallenger(mk *porbjo.MasterKey) *Challenger {
	c := &Challenger{mk: mk}
	c.next.Store(1)
	return c
}

// ChalBytes returns the binary size of a challenge: J(4) + Kjc + U(4).
func (ch *Challenger) ChalBytes(chal line.Challenge) int {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return len(chal)
	}
	return 4 + len(wc.Kjc) + 4
}

func (ch *Challenger) Challenge(_ [][]byte) (line.Challenge, line.Validator, error) {
	j := int(ch.next.Add(1) - 1)
	if j > ch.mk.Params.Q {
		return nil, nil, fmt.Errorf("bjo.Challenge: sentinel index %d exceeds Q=%d", j, ch.mk.Params.Q)
	}
	chal, err := porbjo.MakeChallenge(ch.mk, j)
	if err != nil {
		return nil, nil, fmt.Errorf("bjo.Challenge: %w", err)
	}
	b, err := json.Marshal(wireChal{J: chal.J, Kjc: chal.Kjc, U: chal.U})
	if err != nil {
		return nil, nil, fmt.Errorf("bjo.Challenge: marshal: %w", err)
	}
	return line.Challenge(b), NewValidator(ch.mk), nil
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

// Prover implements line.Prover for the BJO scheme.
type Prover struct {
	s         *suite.Suite
	params    *porbjo.Params
	sentinels [][]byte
}

// NewProver constructs a Prover from the EncodedFile produced by Tagger.TagBlocks.
// Prove will call store.Block(idx) to read encoded blocks.
func NewProver(s *suite.Suite, ef *porbjo.EncodedFile) *Prover {
	return &Prover{s: s, params: ef.Params, sentinels: ef.Sentinels}
}

// NewProverFromWire builds a server-side Prover from wire params and sentinels,
// avoiding the need to import por/bjo directly.
func NewProverFromWire(s *suite.Suite, wp WireParams, sentinels [][]byte) *Prover {
	return &Prover{s: s, params: wp.toParams(), sentinels: sentinels}
}

// ProofBytes returns the binary size of a proof: Mj + Qj byte slices.
func (p *Prover) ProofBytes(proof line.Proof) int {
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return len(proof)
	}
	return len(wp.Mj) + len(wp.Qj)
}

// Prove implements line.Prover. store is called for each challenged encoded block.
func (p *Prover) Prove(chal line.Challenge, store blocks.BlockStore) (line.Proof, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return nil, fmt.Errorf("bjo.Prove: challenge: %w", err)
	}
	resp, err := porbjo.RespondFetch(p.s, p.params, p.sentinels,
		&porbjo.Challenge{J: wc.J, Kjc: wc.Kjc, U: wc.U}, store)
	if err != nil {
		return nil, fmt.Errorf("bjo.Prove: %w", err)
	}
	b, err := json.Marshal(wireProof{Mj: resp.Mj, Qj: resp.Qj})
	if err != nil {
		return nil, fmt.Errorf("bjo.Prove: marshal: %w", err)
	}
	return line.Proof(b), nil
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

// Validator implements line.Validator for the BJO scheme.
type Validator struct {
	mk *porbjo.MasterKey
}

func NewValidator(mk *porbjo.MasterKey) *Validator {
	return &Validator{mk: mk}
}

func (v *Validator) Verify(chal line.Challenge, proof line.Proof) (bool, error) {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return false, fmt.Errorf("bjo.Verify: challenge: %w", err)
	}
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return false, fmt.Errorf("bjo.Verify: proof: %w", err)
	}
	return porbjo.Verify(v.mk,
		&porbjo.Challenge{J: wc.J, Kjc: wc.Kjc, U: wc.U},
		&porbjo.Response{Mj: wp.Mj, Qj: wp.Qj},
	)
}

// ---------------------------------------------------------------------------
// Extractor
// ---------------------------------------------------------------------------

// bjoEquation records the information from one witnessed (challenge, proof) pair.
// Each equation constrains a group of v encoded block field elements:
//
//	M_j = Σ_{pos=0}^{v-1} F̃_{blockPos[pos]} · G[pos+1][u]  mod P
type bjoEquation struct {
	blockPos []int    // v challenged block indices into ef.Blocks
	u        int      // inner code generator column (1-indexed)
	mj       *big.Int // proof value M_j as a Z_P element
}

// Extractor implements line.Extractor for the BJO scheme using passive
// witnessing. Each witnessed (challenge, proof) pair contributes one linear
// equation over Z_P involving the v challenged encoded block field elements.
// Once the accumulated equations form a full-rank system over all t encoded
// blocks, Extract applies the SA-ECC outer decode to recover the original file.
type Extractor struct {
	s    *suite.Suite
	mk   *porbjo.MasterKey
	ef   *porbjo.EncodedFile // carries params, sentinels, MAC, and block length
	t    int                 // total encoded block count (len(ef.Blocks))
	rows []bjoEquation
}

// NewExtractor constructs an Extractor from the EncodedFile produced by
// Tagger.TagBlocks.
func NewExtractor(s *suite.Suite, mk *porbjo.MasterKey, ef *porbjo.EncodedFile) *Extractor {
	return &Extractor{s: s, mk: mk, ef: ef, t: len(ef.Blocks)}
}

// Witness records one validated (challenge, proof) pair. The caller must
// verify the proof before calling Witness.
//
// It derives the v challenged block indices from chal.Kjc (mirroring the
// server's RespondFetch) and stores the inner-code equation for later solving.
func (e *Extractor) Witness(chal line.Challenge, proof line.Proof) error {
	var wc wireChal
	if err := json.Unmarshal(chal, &wc); err != nil {
		return fmt.Errorf("bjo.Extractor.Witness: challenge: %w", err)
	}
	var wp wireProof
	if err := json.Unmarshal(proof, &wp); err != nil {
		return fmt.Errorf("bjo.Extractor.Witness: proof: %w", err)
	}

	// Derive the same v block indices that RespondFetch used (§4.2.1 respond).
	indices := e.s.BuildPRP(wc.Kjc, e.t)[:e.mk.Params.V]

	mj := new(big.Int).SetBytes(wp.Mj)
	e.rows = append(e.rows, bjoEquation{
		blockPos: append([]int(nil), indices...),
		u:        wc.U,
		mj:       mj,
	})
	return nil
}

// Extract solves for all t encoded block field elements from the accumulated
// witnessed proofs, then delegates to the BJO Phase II SA-ECC outer decode
// (via porbjo.Extract with Alpha=0) to recover the original file.
//
// Returns ErrInsufficientProofs if the linear system is not yet full-rank.
func (e *Extractor) Extract() (blocks.BlockStore, error) {
	p := e.mk.Params

	// Build the t×(t+1) augmented matrix.
	// Row r corresponds to equation r:
	//   Σ_{pos} G[pos+1][u_r] · F̃_{blockPos[pos]} = M_j
	// G[row][u] = PRF(GSeed, u, row) mod P  (§4.2.1 inner code)
	aug := make([][]*big.Int, len(e.rows))
	for r, eq := range e.rows {
		aug[r] = make([]*big.Int, e.t+1)
		for k := range aug[r] {
			aug[r][k] = new(big.Int)
		}
		for pos, idx := range eq.blockPos {
			// G[pos+1][u] = PRF(GSeed, u, pos+1) mod P
			g := new(big.Int).Mod(e.s.PRF(p.GSeed, eq.u, pos+1), p.P)
			aug[r][idx].Add(aug[r][idx], g)
			aug[r][idx].Mod(aug[r][idx], p.P)
		}
		aug[r][e.t] = new(big.Int).Set(eq.mj)
	}

	sol := line.GaussElimModP(aug, e.t, p.P)
	if sol == nil {
		return nil, line.ErrInsufficientProofs
	}

	// Reconstruct encoded block bytes from the recovered Z_P field elements.
	// F̃_i = SetBytes(block_i) mod P, so the inverse is: block_i = sol[i].Bytes()
	// padded to the original block length. The extraction property requires
	// P > max(block value) so the mod-P reduction is lossless.
	blockLen := len(e.ef.Blocks[0])
	recoveredBlocks := make([][]byte, e.t)
	for i, fi := range sol {
		b := fi.Bytes()
		block := make([]byte, blockLen)
		if len(b) > blockLen {
			b = b[len(b)-blockLen:]
		}
		copy(block[blockLen-len(b):], b)
		recoveredBlocks[i] = block
	}

	// Phase II: apply SA-ECC outer decode and verify file MAC.
	// Setting Alpha=0 in a params copy tells porbjo.Extract to skip Phase I
	// and use the supplied blocks directly (§4.2.1 extract, Alpha=0 path).
	paramsCopy := *p
	paramsCopy.Alpha = 0
	mkCopy := *e.mk
	mkCopy.Params = &paramsCopy
	syntheticEF := &porbjo.EncodedFile{
		Blocks:     recoveredBlocks,
		NumMessage: e.ef.NumMessage,
		Sentinels:  e.ef.Sentinels,
		FileMAC:    e.ef.FileMAC,
		Params:     &paramsCopy,
	}
	file, err := porbjo.Extract(e.s, &mkCopy, syntheticEF)
	if err != nil {
		return nil, fmt.Errorf("bjo.Extractor.Extract: %w", err)
	}
	return blocks.NewMemStore(file), nil
}
