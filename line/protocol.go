// Package protocol defines wire-layer abstractions over storage-proof schemes.
// Each scheme has a sub-package that implements these interfaces against the
// underlying mathematical protocol packages.
//
// Challenges and proofs are opaque byte slices so that the encoding format
// can evolve independently of the protocol logic.
package line

import (
	"errors"
	"fmt"

	"github.com/pinionengineering/storage-proofs/blocks"
)

// ErrInsufficientProofs is returned by Extractor.Extract when not enough
// challenge-proof pairs have been witnessed to recover the full file.
var ErrInsufficientProofs = errors.New("insufficient proofs for extraction")

// Tag is opaque per-block authentication metadata produced by a Tagger.
type Tag []byte

// TagStore provides on-demand, index-keyed access to a file's tags —
// mirrors blocks.BlockStore's role for block content (Block(id), fetched
// lazily per challenged position). A Prover built from a TagStore only ever
// calls Tag(i) for the specific indices a challenge samples, so a real
// implementation backed by a partitioned, range-readable storage format can
// resolve and fetch each one with a targeted read, never materializing tags
// for the whole file.
type TagStore interface {
	Tag(i int) (Tag, error)
}

// TagMap adapts an already-resolved map to TagStore — for tests, or a
// caller (like ProverFactory.NewProver's dense construction) that already
// has every tag in hand and just needs the same on-demand-lookup shape.
type TagMap map[int]Tag

func (m TagMap) Tag(i int) (Tag, error) {
	t, ok := m[i]
	if !ok {
		return nil, fmt.Errorf("line: TagMap: no tag for index %d", i)
	}
	return t, nil
}

// Challenge is an opaque audit challenge produced by a Challenger.
type Challenge []byte

// Proof is an opaque proof produced by a Prover in response to a Challenge.
type Proof []byte

// Tagger produces authentication tags for a sequence of blocks.
// The returned tags are ordered by block index and are opaque to callers;
// they are passed verbatim to a Prover and Validator at audit time.
type Tagger interface {
	TagBlocks(store blocks.BlockStore) ([]Tag, error)
}

// Challenger generates audit challenges.
type Challenger interface {
	// Challenge produces a fresh challenge for a file whose block identifiers
	// are given by ids (store.IDs() at audit time). The returned bytes are
	// suitable for transmission to a Prover. The returned Validator is bound to
	// this specific challenge round and must be used to verify the corresponding
	// proof.
	Challenge(ids [][]byte) (Challenge, Validator, error)
}

// Prover responds to audit challenges on behalf of the storage server.
type Prover interface {
	Prove(chal Challenge, store blocks.BlockStore) (Proof, error)
}

// Validator verifies proofs returned by a Prover.
type Validator interface {
	// Verify returns true iff proof is a valid response to chal.
	Verify(chal Challenge, proof Proof) (bool, error)
}

// Extractor recovers the original file by accumulating witnessed challenge-proof
// transcripts. Call Witness for each valid (challenge, proof) pair observed;
// the caller is responsible for verifying proofs before passing them. Call
// Extract once enough transcripts have been collected.
type Extractor interface {
	Witness(chal Challenge, proof Proof) error
	Extract() (blocks.BlockStore, error)
}

// ExtractorProducer is implemented by Taggers that support file extraction.
// NewExtractor must be called after TagBlocks.
type ExtractorProducer interface {
	NewExtractor() (Extractor, error)
}

// SetupProducer is implemented by Taggers after TagBlocks has been called.
// It provides the artifacts needed by both sides of the audit protocol.
type SetupProducer interface {
	// ProverSetup returns the opaque payload to send to the prover server.
	ProverSetup() ([]byte, error)
	// ClientSetup returns the opaque payload the client retains for auditing.
	// Pass it to ChallengerFactory.NewChallenger to reconstruct a Challenger.
	ClientSetup() ([]byte, error)
	// EncodedBlocks returns the blocks the prover server should store.
	// For protocols that transform the file (e.g. BJO), this differs from the
	// input; for others it is the same store passed to TagBlocks.
	EncodedBlocks() blocks.BlockStore
}

// ProverFactory builds a Prover on the server side from a setup payload
// produced by SetupProducer.ProverSetup. store holds the blocks the server
// has already stored.
type ProverFactory interface {
	NewProver(setup []byte, store blocks.BlockStore) (Prover, error)
}

// SparseProverFactory is implemented by ProverFactories whose Prover can be
// constructed from a TagStore instead of the full dense tag array NewProver
// requires. The returned Prover only ever calls TagStore.Tag(i) for the
// specific indices its own challenge-derivation picks — the same point in
// its existing Prove() flow that already needs those indices for other
// reasons — so no separate up-front "learn which indices, then fetch, then
// construct" step is needed: the caller builds a TagStore once (e.g. backed
// by a targeted storage range-read per index) and hands it over.
//
// This does not change the cost of deriving *which* indices a challenge
// samples — line.DeriveChallenge and suite.BuildPRP both still rank every
// block identifier to pick the sampled subset, an existing O(N) cost. What
// it removes is the cost of fetching tag *data* for the whole file once the
// sampled positions are known — that part drops from O(N) to O(len(indices)).
type SparseProverFactory interface {
	ProverFactory
	// NewProverFromTagStore builds a Prover that fetches tags on demand from
	// tags, instead of requiring the full dense tag list NewProver does.
	NewProverFromTagStore(setup []byte, tags TagStore) (Prover, error)
}

// ChallengerFactory builds a Challenger from a client setup blob produced by
// SetupProducer.ClientSetup. c is the number of blocks sampled per challenge;
// schemes that bake this into their parameters (sw, bjo) ignore it.
type ChallengerFactory interface {
	NewChallenger(setup []byte, c int) (Challenger, error)
}

// ChalSizer is implemented by Challengers that can report the binary
// (non-JSON) byte count of a challenge message.
type ChalSizer interface {
	ChalBytes(Challenge) int
}

// ProofSizer is implemented by Provers that can report the binary
// (non-JSON) byte count of a proof message.
type ProofSizer interface {
	ProofBytes(Proof) int
}
