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
// Indices are positions in store.IDs() ordering, corresponding to (i_t) in
// the challenge (i_t, ν_t) of §3.2 (private) and §3.3 (public). Coeffs are
// blinding scalars ν_t in Z_P (PrivKind) or Z_q/curve order (PubKind).
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

	// TagBlocks computes one serialized tag per block. The client uploads
	// (blocks, tags) to the server and retains only the key material embedded
	// in the Scheme instance.
	TagBlocks(store blocks.BlockStore) ([][]byte, error)

	// MakeChallenge returns a fresh random challenge sampling l of the given
	// block IDs (capped to len(ids)). For PubKind, any holder of the public
	// key can call this.
	MakeChallenge(ids [][]byte, l int) (*SWChallenge, error)

	// RespondFetch computes a proof by fetching the challenged blocks on demand.
	// Called by the server; requires only the serialized tags and a block store.
	RespondFetch(tags [][]byte, chal *SWChallenge, store blocks.BlockStore) (*SWProof, error)

	// Verify checks the server's proof against a challenge. ids is the ordered
	// identifier list from store.IDs() at audit time; it is used by PubKind to
	// reconstruct H(λ‖id_t) per §3.3 and ignored by PrivKind (§3.2 uses only
	// integer positions for the PRF).
	Verify(chal *SWChallenge, proof *SWProof, ids [][]byte) (bool, error)
}
