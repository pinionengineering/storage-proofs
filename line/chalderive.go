package line

// DeriveChallenge deterministically selects n distinct block positions and
// generates n blinding coefficients in [0, modulus) from a seed and an
// ordered list of block identifiers.
//
// # Index selection
//
// Each block position i is ranked by HMAC-SHA256(idxKey, ids[i]), where
// idxKey = HMAC-SHA256(seed, "indices"). Positions are sorted by rank and
// the first n taken. This is a keyed hash-sort: given the same (seed, ids),
// the selection is deterministic and uniformly distributed without replacement.
//
// # Coefficient derivation
//
// Coefficients are suite.PRF(coeffKey, t) mod modulus for t = 0..n-1, where
// coeffKey = HMAC-SHA256(seed, "coeffs").
//
// # Stateless verification
//
// Because derivation is deterministic, both the prover and the validator can
// independently reproduce (indices, coeffs) from (seed, ids, n, modulus).
// Only (seed, n, C) need to travel on the wire. The prover supplies ids from
// store.IDs(); the validator supplies ids captured at Challenge time.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
	"sort"

	"github.com/pinionengineering/storage-proofs/suite"
)

// DeriveChallenge derives n block positions and n blinding coefficients from
// seed, the ordered identifier list ids, and a field modulus.
func DeriveChallenge(s *suite.Suite, seed []byte, ids [][]byte, n int, modulus *big.Int) ([]int, []*big.Int) {
	if n > len(ids) {
		n = len(ids)
	}

	idxKey := chalDeriveKey(seed, "indices")
	coeffKey := chalDeriveKey(seed, "coeffs")

	type ranked struct {
		pos  int
		rank []byte
	}
	ranks := make([]ranked, len(ids))
	for i, id := range ids {
		mac := hmac.New(sha256.New, idxKey)
		mac.Write(id)
		ranks[i] = ranked{pos: i, rank: mac.Sum(nil)}
	}
	sort.Slice(ranks, func(i, j int) bool {
		return bytes.Compare(ranks[i].rank, ranks[j].rank) < 0
	})

	indices := make([]int, n)
	for i := range n {
		indices[i] = ranks[i].pos
	}

	coeffs := make([]*big.Int, n)
	for t := range n {
		coeffs[t] = new(big.Int).Mod(s.PRF(coeffKey, t), modulus)
	}

	return indices, coeffs
}

func chalDeriveKey(seed []byte, label string) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}
