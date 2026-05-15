package sw

import (
	"math/big"

	"github.com/pinionengineering/storage-proofs/blocks"
)

// SchemeKind identifies which SW verification variant a challenge or proof belongs to.
type SchemeKind uint8

const (
	// PrivKind is the private-key scheme from §3.2: verification requires the
	// client's secret key (K, α). No pairings; unlimited audits.
	PrivKind SchemeKind = iota
	// PubKind is the public-key scheme from §3.3: verification requires only
	// the public key v = g^α. Anyone with v can audit; each audit costs two
	// bilinear pairing evaluations.
	PubKind
)

// SWChallenge is the common challenge type for both SW scheme variants.
// Coeffs are blinding scalars in Z_P (PrivKind) or Z_q/curve order (PubKind).
type SWChallenge struct {
	Kind    SchemeKind
	Indices []int
	Coeffs  []*big.Int
}

// SWProof is the common proof type for both SW scheme variants.
// Sigma is serialized: big-endian Z_P bytes for PrivKind, a 64-byte G1 marshal
// for PubKind. Mu holds S sector aggregates in the appropriate field.
type SWProof struct {
	Sigma []byte
	Mu    []*big.Int
}

// Scheme is the common interface for both SW storage-proof variants.
// Tags and sigma are serialized to []byte so the server is scheme-agnostic.
type Scheme interface {
	Kind() SchemeKind

	// TagFile computes one serialized tag per block. The client uploads
	// (file, tags) to the server and retains only the key material embedded
	// in the Scheme instance.
	TagFile(store blocks.BlockStore) ([][]byte, error)

	// MakeChallenge returns a fresh random challenge for a file of n blocks.
	// For PubKind, any holder of the public key can call this.
	MakeChallenge(n int) (*SWChallenge, error)

	// RespondFetch computes a proof by fetching the challenged blocks on demand.
	// Called by the server; requires only the serialized tags and a block store.
	RespondFetch(tags [][]byte, chal *SWChallenge, store blocks.BlockStore) (*SWProof, error)

	// Verify checks the server's proof against a challenge.
	// For PrivKind the embedded secret key is used; for PubKind only the
	// embedded public key is required.
	Verify(chal *SWChallenge, proof *SWProof) (bool, error)
}
