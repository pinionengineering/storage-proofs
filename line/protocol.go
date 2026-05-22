// Package protocol defines wire-layer abstractions over storage-proof schemes.
// Each scheme has a sub-package that implements these interfaces against the
// underlying mathematical protocol packages.
//
// Challenges and proofs are opaque byte slices so that the encoding format
// can evolve independently of the protocol logic.
package line

import "github.com/pinionengineering/storage-proofs/blocks"

// Tag is opaque per-block authentication metadata produced by a Tagger.
type Tag []byte

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

// Extractor recovers the original file blocks from a server that answers
// sufficiently many challenges honestly. Only POR protocols implement this.
type Extractor interface {
	Extract(store blocks.BlockStore) (blocks.BlockStore, error)
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
