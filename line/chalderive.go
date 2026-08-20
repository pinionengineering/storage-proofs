package line

// DeriveChallenge deterministically selects n distinct block positions and
// generates n blinding coefficients in [0, modulus) from a seed and total
// candidate positions resolved one at a time via idAt.
//
// # Index selection
//
// Each candidate position i is ranked by HMAC-SHA256(idxKey, idAt(i)),
// where idxKey = HMAC-SHA256(seed, "indices"). The n positions with the
// smallest rank are selected, in ascending rank order -- a keyed hash-sort,
// computed here via a bounded max-heap of size n (see rankHeap) rather than
// sorting all total ranks, so this costs O(total) time but only O(n)
// memory regardless of how large total is. idAt's own return value is
// never retained past the single HMAC.Write call that consumes it, so
// nothing proportional to total is ever held in memory at once either.
//
// This replaced an implementation that took ids [][]byte -- every
// candidate's identifier pre-materialized by the caller -- and fully
// sorted it. That cost was O(total) in both time *and* memory, which for a
// chunked/super-block protocol means memory scaled with the tagged file's
// total size, not with n (the actual number of blocks challenged): a
// hydrogen incident on 2026-08-19/20 saw an n=1000 challenge against a
// total=4,894,287 super-block file cost 500MB+ just deciding which 1000 to
// challenge, before any actual proof computation began.
//
// # Coefficient derivation
//
// Coefficients are suite.PRF(coeffKey, t) mod modulus for t = 0..n-1, where
// coeffKey = HMAC-SHA256(seed, "coeffs").
//
// # Stateless verification
//
// Because derivation is deterministic, both the prover and the validator can
// independently reproduce (indices, coeffs) from (seed, total, idAt, n,
// modulus). Only (seed, n, C) need to travel on the wire. The prover
// resolves idAt from store.IDs()/IDAt (see blocks.IDAtFunc); the validator
// resolves it from ids captured at Challenge time.
import (
	"bytes"
	"container/heap"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
	"sort"

	"github.com/pinionengineering/storage-proofs/suite"
)

// DeriveChallenge derives n block positions (out of total candidates,
// resolved via idAt) and n blinding coefficients from seed and a field
// modulus.
func DeriveChallenge(s *suite.Suite, seed []byte, total int, idAt func(int) []byte, n int, modulus *big.Int) ([]int, []*big.Int) {
	if n > total {
		n = total
	}

	idxKey := chalDeriveKey(seed, "indices")
	coeffKey := chalDeriveKey(seed, "coeffs")

	// h always holds the n smallest-rank candidates seen so far; h[0] is
	// the worst (largest rank) of those n, so each new candidate only
	// needs comparing against h[0] to decide whether it displaces
	// something. Once every candidate has been considered, h necessarily
	// holds the n globally smallest-rank candidates -- the same set a full
	// sort's first n entries would hold, just without ever holding more
	// than n at once.
	h := make(rankHeap, 0, n)
	for i := range total {
		mac := hmac.New(sha256.New, idxKey)
		mac.Write(idAt(i))
		r := ranked{pos: i, rank: mac.Sum(nil)}
		switch {
		case len(h) < n:
			heap.Push(&h, r)
		case bytes.Compare(r.rank, h[0].rank) < 0:
			h[0] = r
			heap.Fix(&h, 0)
		}
	}
	sort.Slice(h, func(i, j int) bool { return bytes.Compare(h[i].rank, h[j].rank) < 0 })

	indices := make([]int, n)
	for i := range n {
		indices[i] = h[i].pos
	}

	coeffs := make([]*big.Int, n)
	for t := range n {
		coeffs[t] = new(big.Int).Mod(s.PRF(coeffKey, t), modulus)
	}

	return indices, coeffs
}

type ranked struct {
	pos  int
	rank []byte
}

// rankHeap is a container/heap max-heap by rank: Less is reversed from the
// usual ascending order so Pop/h[0] always yields the current worst
// (largest-rank) kept candidate, letting DeriveChallenge decide in
// O(log n) whether each new candidate should displace it.
type rankHeap []ranked

func (h rankHeap) Len() int           { return len(h) }
func (h rankHeap) Less(i, j int) bool { return bytes.Compare(h[i].rank, h[j].rank) > 0 }
func (h rankHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rankHeap) Push(x any)        { *h = append(*h, x.(ranked)) }
func (h *rankHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func chalDeriveKey(seed []byte, label string) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}
