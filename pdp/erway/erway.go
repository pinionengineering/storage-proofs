// Package erway implements Dynamic Provable Data Possession I (DPDP I) from
// "Dynamic Provable Data Possession" by Erway, Küpçü, Papamanthou, and
// Tamassia (ACM CCS 2009), saved at
// doc/dynamic-provable-data-possession.pdf. Section references throughout
// this package (§) are to that paper unless stated otherwise.
//
// # Overview
//
// DPDP I extends static PDP to support provable updates (insert, modify,
// delete) on the outsourced file. The server maintains a rank-based
// authenticated skip list whose leaves hold block tags T(b) = g^b mod N
// (§4.2). The client retains only a single 32-byte basis: the label of
// the skip list's start node (§3.1, §4.1), kept as O(1) metadata (§4,
// Theorem 1).
//
// # Three papers, one skip list
//
// Erway et al.'s own Definition 3 (§3.1) gives every node's label the
// unconditional form h(level, rank, down, right). Since right(v)'s label
// there recursively embeds everything to its own right, a single edit's
// effect on the digest is unbounded, which forces a full rebuild on every
// edit and rules out any bounded, client-side update-verification
// algorithm. Erway's own §3.4 acknowledges this gap and defers to a
// different paper for the technique: Papamanthou & Tamassia, "Time and
// Space Efficient Algorithms for Two-Party Authenticated Data Structures"
// (ICICS 2007, doc/time-space-efficient-two-party-authenticated-data-
// structures.pdf), which in turn defers the underlying node-labeling
// scheme to a third paper: Goodrich, Tamassia & Schwerin, "Implementation
// of an Authenticated Dictionary with Skip Lists and Commutative Hashing"
// (DISCEX 2001, doc/commutative-hashing-authenticated-dictionary.pdf).
// This package's skip list uses that third paper's own node-labeling
// scheme in place of Definition 3.
//
// Concretely:
//   - The node-labeling function f (see its doc) is that third paper's
//     §4.2, ported from its key-ordered dictionary to this package's
//     rank-ordered blocks. The "tower"/"plateau" distinction and the fixed
//     maxSkipListHeight (see its doc) both come from there.
//   - Everything about a single challenged block (atRank, BlockProof,
//     ProofStep, verifyPath, Challenge/Prove/Verify) follows Erway's own
//     Algorithms 1-2 and §4.1-4.2 directly; see each function's doc for
//     the exact correspondence.
//   - Deriving a new basis from a bounded old proof (PerformUpdate,
//     VerifyUpdate, deriveBasisAfterInsert) follows Erway's own Algorithms
//     3-4 for the overall shape (query, verify, update, return). The
//     digest arithmetic itself is re-derived against f, since
//     Papamanthou-Tamassia's own Figure 2 is written for a different
//     (sequential-hash) labeling scheme. OpDelete specifically follows
//     that paper's own §3.2 technique, "reduce an authenticated deletion
//     to an authenticated insertion."
//   - A handful of pieces (atInsertionPoint, verifyInsertionPoint,
//     foldOwnTower) have no named counterpart in any of the three papers:
//     they're this package's own scaffolding, needed to make the above
//     compose correctly under the tower/plateau formula. Each says so in
//     its own doc, along with what role it plays.
package erway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/suite"
)

// ─── Key and tag ─────────────────────────────────────────────────────────────

// KeyGen generates a public key for DPDP I. Unlike the Ateniese scheme,
// DPDP I needs no secret key (§4.1).
func KeyGen(k int) (*pdp.PublicKey, error) {
	pk, err := pdp.MakePublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("erway.KeyGen: %w", err)
	}
	return pk, nil
}

// BlockTag computes T(b) = g^b mod N for block data b (§4.2).
func BlockTag(s *suite.Suite, pk *pdp.PublicKey, block []byte) *big.Int {
	return new(big.Int).Exp(pk.G, new(big.Int).SetBytes(block), pk.N)
}

// ─── Hash primitives ──────────────────────────────────────────────────────────

var nullLabel = make([]byte, 32)

// nodeHash implements h(x₁,…,xₖ) = SHA-256(SHA-256(x₁)‖…‖SHA-256(xₖ)).
func nodeHash(args ...[]byte) []byte {
	var combined []byte
	for _, a := range args {
		h := sha256.Sum256(a)
		combined = append(combined, h[:]...)
	}
	out := sha256.Sum256(combined)
	return out[:]
}

func equal32(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ─── Skip list ────────────────────────────────────────────────────────────────

// zeroEntry is elem(v) for a level-0 node v in the sense of
// Goodrich-Tamassia-Schwerin §4.2 (see f, below): its raw, unhashed value.
// It holds a data block's own rank (always 1) and tag, or the level-0
// sentinel's (rank 0, tag nil).
type zeroEntry struct {
	Rank int
	Tag  []byte
}

func (z zeroEntry) bytes() []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(z.Rank))
	tag := z.Tag
	if tag == nil {
		tag = nullLabel
	}
	return append(buf[:], tag...)
}

// elem(v) is Goodrich-Tamassia-Schwerin §4.2's own notation for a base-level
// node's raw value, the thing f hashes at the bottom of the skip list.
func elem(v *slNode) []byte {
	return zeroEntry{Rank: v.rank, Tag: v.tag}.bytes()
}

func zeroEntryOf(v *slNode) zeroEntry {
	return zeroEntry{Rank: v.rank, Tag: v.tag}
}

// slNode is one node in the authenticated skip list.
//
//   - rank: count of data blocks "owned" by this node. It's 1 for a level-0
//     data node, 0 for a level-0 sentinel, and (for level≥1) the count of
//     bottom-level data nodes from this node's bottom projection (inclusive)
//     up to, but not including, the bottom projection of its right neighbour.
//   - tag: T(block).Bytes() for level-0 data nodes only.
//   - left: the predecessor at the same level, maintained alongside right.
//   - up: the level+1 node whose down pointer is this node, if any. This
//     is exactly what distinguishes a "tower" node (up != nil) from a
//     "plateau" node (up == nil) in f, below.
type slNode struct {
	level       int
	right, left *slNode
	down, up    *slNode
	rank        int
	tag         []byte // non-nil only for level-0 data nodes
	isSentinel  bool
}

// isTower reports whether v also has a presence one level up. This is
// Goodrich, Tamassia & Schwerin, "Implementation of an Authenticated
// Dictionary with Skip Lists and Commutative Hashing" (DISCEX 2001),
// §4.2's own distinction between a "tower" element (also present at the
// next level up) and a "plateau" element (this is as high as it goes).
func isTower(v *slNode) bool {
	return v != nil && v.up != nil
}

// f is exactly §4.2's node-labeling function, ported from that paper's
// key-ordered dictionary to this package's rank-ordered blocks: for a node
// v with w = right(v) and u = down(v),
//
//  1. u == nil (v is on the base level):
//     (a) w is a tower node: f(v) = h(elem(v), elem(w)).
//     (b) w is a plateau node: f(v) = h(elem(v), f(w)).
//  2. u != nil (v is not on the base level):
//     (a) w is a tower node: f(v) = f(u).
//     (b) w is a plateau node: f(v) = h(f(u), f(w)).
//
// (If w == nil, f(v) = 0, nullLabel here.) This package uses this formula
// in place of Erway et al.'s own Definition 3 (§3.1 of the DPDP paper),
// which gives every node's label the unconditional form
// h(level, rank, down, right). Since right(v)'s label there recursively
// embeds everything to its own right, a single edit's effect on the digest
// is unbounded there, which is fine for a static construction but defeats
// any bounded, client-side update-verification; §3.4 of that paper
// explicitly defers to this technique for exactly that reason (see
// PerformUpdate/VerifyUpdate). Under the tower/plateau split, only case
// 1(b)/2(b) ever recurses rightward, and the run of consecutive plateau
// nodes before the next tower has expected length O(1) (each element
// independently has a 50% chance of continuing up), so every call to f is
// expected O(1). That's also why labels are never cached here: there is no
// stale-cache failure mode to guard against when nothing is ever cached
// (an earlier, cache-based version of this package during development had
// exactly that bug).
func f(v *slNode) []byte {
	w := v.right
	if w == nil {
		return nullLabel
	}
	if v.level == 0 { // v is on the base level (u == nil)
		if isTower(w) {
			return nodeHash(elem(v), elem(w)) // case 1(a)
		}
		return nodeHash(elem(v), f(w)) // case 1(b)
	}
	if isTower(w) {
		return f(v.down) // case 2(a)
	}
	var lEnc, rEnc [8]byte
	binary.BigEndian.PutUint64(lEnc[:], uint64(v.level))
	binary.BigEndian.PutUint64(rEnc[:], uint64(v.rank))
	return nodeHash(lEnc[:], rEnc[:], f(v.down), f(w)) // case 2(b), plus Erway's own level/rank binding (Definition 3) folded in
}

// maxSkipListHeight is the fixed number of levels every SkipList is built
// with, per both Goodrich-Tamassia-Schwerin's and Papamanthou-Tamassia's own
// reference designs. The former states outright "the highest level of a
// tower was limited to 20" (§5), and the latter's proof-size accounting
// budgets a fixed log(maxlevel) bits per step with maxlevel=20 in its own
// experiments (§4, Experimental Results). Neither structure grows a new
// top level dynamically.
// That avoids a real correctness hazard for Insert's
// update-verification: dynamic growth would, as a side effect, flip the
// *old* top level's own right sentinel from plateau to tower, which can
// silently invalidate values folded through it (including ones nowhere
// near the actual insert position) that a bounded, previously-captured
// proof has no way to detect or recompute. Given the geometric height
// distribution (each level has ~50% of the previous level's population),
// 64 levels comfortably covers any n up to roughly 2^64 blocks, so this
// costs nothing observable in practice. just 64 fixed sentinel-pair nodes
// per skip list, and a bounded number of extra pass-through steps in every
// proof (still O(log n) asymptotically, since 64 is a constant).
const maxSkipListHeight = 64

// SkipList is the server-side rank-based authenticated skip list.
//
// levels[i] is the leftmost (sentinel) node at level i. len(levels) is
// always maxSkipListHeight (see its doc); the structure never grows or
// shrinks.
type SkipList struct {
	levels  []*slNode // levels[i] = leftmost node at level i
	n       int       // count of data blocks
	heights []int     // per-block tower height chosen at insertion time
}

// Heights returns the tower height chosen for each block at insertion time,
// in block order. The paper (§3.4) specifies that the client chooses heights
// and sends them to the server as part of the insertion parameters; Heights
// provides the values needed to reconstruct an identical skip list via BuildWithHeights.
func (sl *SkipList) Heights() []int {
	out := make([]int, len(sl.heights))
	copy(out, sl.heights)
	return out
}

// Basis is the DPDP paper's own "basis" (§4.1): the O(1) client metadata a
// verifier retains between operations. It is exactly f(s), the label of the
// skip list's start node s (§3.1); see startLabel.
type Basis []byte

// Clone returns an independent copy.
func (b Basis) Clone() Basis {
	c := make(Basis, len(b))
	copy(c, b)
	return c
}

// startLabel is f(s) for the start node s: "the top leftmost node of a skip
// list" (§3.1). Its label is the basis (see Basis's doc).
func (sl *SkipList) startLabel() []byte {
	return f(sl.levels[len(sl.levels)-1])
}

// ─── Build ────────────────────────────────────────────────────────────────────

// newEmptySkipList creates a SkipList with its full, fixed set of
// maxSkipListHeight linked sentinel-pair levels (see maxSkipListHeight's doc).
func newEmptySkipList() *SkipList {
	levels := make([]*slNode, maxSkipListHeight)
	var prevLeft, prevRight *slNode
	for lvl := range maxSkipListHeight {
		right := &slNode{level: lvl, isSentinel: true}
		left := &slNode{level: lvl, isSentinel: true, right: right}
		right.left = left
		if prevLeft != nil {
			left.down = prevLeft
			right.down = prevRight
			prevLeft.up = left
			prevRight.up = right
		}
		levels[lvl] = left
		prevLeft, prevRight = left, right
	}
	return &SkipList{levels: levels}
}

// Build initialises a SkipList for the given blocks and returns the skip
// list (server) and the initial basis (client). This is the "first run"
// case of §4.1's PerformUpdate, which "builds the skip list from scratch
// if this is the first run."
func Build(s *suite.Suite, pk *pdp.PublicKey, store blocks.BlockStore) (*SkipList, Basis, error) {
	if store.Len() == 0 {
		return nil, nil, fmt.Errorf("erway.Build: blocks must not be empty")
	}

	sl := newEmptySkipList()

	for i := range store.Len() {
		b, err := store.Block(blocks.IntID(i))
		if err != nil {
			return nil, nil, fmt.Errorf("erway.Build: block %d: %w", i, err)
		}
		if err := sl.appendBlock(s, pk, b); err != nil {
			return nil, nil, fmt.Errorf("erway.Build: block %d: %w", i, err)
		}
	}

	basis := make(Basis, 32)
	copy(basis, sl.startLabel())
	return sl, basis, nil
}

// coinHeight returns a random tower height using a geometric distribution
// (p=1/2). Per §3.4, tower heights for Insert are chosen by the client; the
// server never calls this for anything but the client-facing helper below.
func coinHeight(max int) int {
	if max <= 1 {
		return 1
	}
	h := 1
	for h < max {
		b := make([]byte, 1)
		rand.Read(b)
		if b[0]&1 == 0 {
			break
		}
		h++
	}
	return h
}

// ChooseHeight draws a tower height for inserting into a list that currently
// has n blocks, using the same geometric distribution the server uses during
// Build. Callers preparing an Insert UpdateOp should call this client-side
// (§3.4: "the client decides the height of the tower").
func ChooseHeight(n int) int {
	return coinHeight(maxHeightFor(n))
}

// maxHeightFor computes a sensible height cap for a list of n blocks,
// never exceeding the skip list's fixed maxSkipListHeight.
func maxHeightFor(n int) int {
	h := 2
	for (1<<h) < n+4 && h < maxSkipListHeight {
		h++
	}
	return h
}

func (sl *SkipList) maxHeight() int {
	return maxHeightFor(sl.n)
}

// appendBlock inserts a new block at the end of the list (position n+1),
// choosing its tower height by coin-flip and recording it.
func (sl *SkipList) appendBlock(s *suite.Suite, pk *pdp.PublicKey, block []byte) error {
	h := coinHeight(sl.maxHeight())
	sl.heights = append(sl.heights, h)
	return sl.doInsert(s, pk, sl.n+1, block, h)
}

// BuildWithHeights constructs a SkipList using caller-supplied tower heights
// instead of drawing them at random. heights[i] is the tower height for block i.
// This lets the server-side prover reproduce the exact structure the client built,
// as required by the paper (§3.4): "the parameters [of an insertion] include the tower height."
func BuildWithHeights(s *suite.Suite, pk *pdp.PublicKey, store blocks.BlockStore, heights []int) (*SkipList, Basis, error) {
	n := store.Len()
	if n == 0 {
		return nil, nil, fmt.Errorf("erway.BuildWithHeights: blocks must not be empty")
	}
	if len(heights) != n {
		return nil, nil, fmt.Errorf("erway.BuildWithHeights: need %d heights, got %d", n, len(heights))
	}

	sl := newEmptySkipList()
	sl.heights = make([]int, n)
	copy(sl.heights, heights)

	for i := range n {
		b, err := store.Block(blocks.IntID(i))
		if err != nil {
			return nil, nil, fmt.Errorf("erway.BuildWithHeights: block %d: %w", i, err)
		}
		if err := sl.doInsert(s, pk, sl.n+1, b, heights[i]); err != nil {
			return nil, nil, fmt.Errorf("erway.BuildWithHeights: block %d: %w", i, err)
		}
	}

	basis := make(Basis, 32)
	copy(basis, sl.startLabel())
	return sl, basis, nil
}

// findPreds locates, for each level in [0, len(sl.levels)), the predecessor
// of 1-indexed position pos (the last existing node occupying a position ≤
// pos-1) and the count of blocks strictly to that predecessor's left at
// that level. This is shared by doInsert (splice after the predecessor;
// passedAt is needed there to split a wide-spanning predecessor's rank
// correctly, see doInsert) and by the incremental-maintenance helpers.
//
// The traversal is §3.1's own rank-based navigation ("we can reach the i-th
// node of the bottom level by traversing a path that begins at the start
// node..."), using low(v)/high(v) computed on the fly from ranks exactly as
// described there. It stops one position early, at the predecessor of pos
// rather than pos itself, since that's what Insert needs to splice after.
//
// Traversal invariant: passed = number of data blocks strictly to the left
// of v. v owns positions (passed, passed+v.rank]. We go right from v to w
// only while w still ends at or before pos-1, i.e. while pos > passed+v.rank+1.
func (sl *SkipList) findPreds(pos int) (preds []*slNode, passedAt []int) {
	preds = make([]*slNode, len(sl.levels))
	passedAt = make([]int, len(sl.levels))
	v := sl.levels[len(sl.levels)-1]
	passed := 0
	for lvl := len(sl.levels) - 1; lvl >= 0; lvl-- {
		for {
			w := v.right
			if w == nil || w.isSentinel {
				break
			}
			if pos > passed+v.rank+1 {
				passed += v.rank
				v = w
			} else {
				break
			}
		}
		preds[lvl] = v
		passedAt[lvl] = passed
		if lvl > 0 {
			if v.down != nil {
				v = v.down
			} else {
				v = sl.levels[lvl-1]
			}
		}
	}
	return preds, passedAt
}

// locateNode finds the existing level-0 node at 1-indexed position pos,
// using the same §3.1 rank-based traversal as findPreds (see its doc), but
// stopping exactly at pos rather than its predecessor. Shared by modifyAt
// and deleteAt, which need the actual node pointer to mutate (unlike
// atRank, which builds proof data from the same descent).
func (sl *SkipList) locateNode(pos int) (*slNode, error) {
	if pos < 1 || pos > sl.n {
		return nil, fmt.Errorf("pos=%d out of range [1,%d]", pos, sl.n)
	}
	v := sl.levels[len(sl.levels)-1]
	passed := 0
	for v.down != nil || v.level > 0 {
		w := v.right
		if w != nil && !w.isSentinel && pos > passed+v.rank {
			passed += v.rank
			v = w
			continue
		}
		if v.down != nil {
			v = v.down
			continue
		}
		break
	}
	for {
		if !v.isSentinel && passed+1 == pos {
			return v, nil
		}
		if !v.isSentinel {
			passed++
		}
		v = v.right
		if v == nil {
			return nil, fmt.Errorf("pos=%d walked off the end of level 0", pos)
		}
	}
}

// atInsertionPoint has no counterpart named in any of the three papers.
// Erway's own atRank(i) (Algorithm 1) only proves an *existing* block, and
// this package's rank-ordered, tower/plateau-labeled skip list has no
// direct analogue of Papamanthou-Tamassia's key-ordered non-membership
// proof path Λ(x) (§3.1: "the client gets the proof path Λ(x)
// (non-membership proof) together with the vectors Lx and Dx", used by
// insert(x, ℓ), §3.2). It plays the same role that non-membership proof
// plays there, though: a verifiable statement of exactly what the tree
// looks like at the point a new element is about to be spliced in, bounded
// to O(log n), which VerifyUpdate's OpInsert case (deriveBasisAfterInsert)
// then folds through the same way Figure 2's update() folds through Q(x).
//
// It builds a proof of the predecessor chain that findPreds(pos) would
// walk, prior to inserting at 1-indexed position pos: the same per-level
// "go right while possible, then go down" traversal, packaged as a
// BlockProof exactly like atRank's (Target is the level-0 predecessor,
// which may be the level-0 left sentinel if pos == 1, plus TargetRightVal
// and the Steps chain up to the root). Unlike atRank, no level gets
// special treatment, since findPreds' own rank-based stopping condition
// already lands precisely at level 0 without a separate scan.
//
// The second return value is, for each level, the cumulative block count
// strictly left of that level's predecessor (findPreds' own passedAt).
// Callers deriving a post-insert basis need it to replicate doInsert's
// rank-splitting locally; verifyInsertionPoint itself does not need it.
func (sl *SkipList) atInsertionPoint(pos int) (BlockProof, []int, error) {
	if pos < 1 || pos > sl.n+1 {
		return BlockProof{}, nil, fmt.Errorf("erway.atInsertionPoint: pos=%d out of range [1,%d]", pos, sl.n+1)
	}

	type entry struct {
		node      *slNode
		wentRight bool
	}
	var path []entry
	passedAt := make([]int, len(sl.levels))

	v := sl.levels[len(sl.levels)-1]
	passed := 0
	for {
		w := v.right
		if w != nil && !w.isSentinel && pos > passed+v.rank+1 {
			path = append(path, entry{v, true})
			passed += v.rank
			v = w
			continue
		}
		passedAt[v.level] = passed
		if v.level > 0 {
			path = append(path, entry{v, false})
			if v.down != nil {
				v = v.down
			} else {
				v = sl.levels[v.level-1]
			}
			continue
		}
		break
	}

	target := zeroEntryOf(v)
	targetRightVal := rightValFor(v)

	var steps []ProofStep
	for i := len(path) - 1; i >= 0; i-- {
		e := path[i]
		node := e.node
		var step ProofStep
		step.Level = node.level
		step.Rank = node.rank
		if e.wentRight {
			step.Right = true
			step.SibLabel = downValueFor(node)
		} else {
			step.Right = false
			w := node.right
			if isTower(w) {
				step.TowerPassthrough = true
			} else {
				step.SibLabel = f(w)
			}
		}
		steps = append(steps, step)
	}

	return BlockProof{Target: target, TargetRightVal: targetRightVal, Steps: steps}, passedAt, nil
}

// verifyInsertionPoint plays the same role for atInsertionPoint's proof
// that Papamanthou-Tamassia's own verify(Q(x)) plays for a non-membership
// query (§3.3: "it sequentially hashes Q(x) to see if the computed digest
// matches the existing one"): it checks that proof authentically represents
// the predecessor chain findPreds(pos) would produce in the tree committed
// to by basis, immediately before inserting at 1-indexed position pos.
// Unlike verifyPath (Algorithm 2, which requires landing exactly on a real
// block, Target.Rank == 1, at position pos), here the target may be a
// sentinel (Rank == 0, the pos == 1 case) and its span must end at exactly
// pos-1, not pos.
func verifyInsertionPoint(basis Basis, pos int, proof BlockProof) (bool, error) {
	gamma := reconstructRoot(proof)
	if !equal32(gamma, []byte(basis)) {
		return false, nil
	}
	posCheck := proof.Target.Rank
	for _, step := range proof.Steps {
		if step.Right {
			posCheck += step.Rank
		}
	}
	return posCheck == pos-1, nil
}

// doInsert is the server-side mutation for Algorithm 3 (performUpdate)
// line 8, "insert element T in the skip [list] after the i-th element",
// for an insertion at 1-indexed position pos with tower height h. All
// existing nodes at positions ≥ pos shift right; line 14's "update the
// labels, levels and ranks of the affected nodes" needs no separate step
// here, since f (this package's replacement for Definition 3, see its doc)
// is never cached in the first place.
func (sl *SkipList) doInsert(s *suite.Suite, pk *pdp.PublicKey, pos int, block []byte, h int) error {
	if h > maxSkipListHeight {
		return fmt.Errorf("erway.doInsert: height %d exceeds maxSkipListHeight %d", h, maxSkipListHeight)
	}
	tagBytes := BlockTag(s, pk, block).Bytes()

	preds, passedAt := sl.findPreds(pos)

	// Build the new tower of h nodes, splicing each in after preds[lvl].
	//
	// preds[lvl] may span more than just the insertion point, e.g. a
	// sentinel that has absorbed several untowered blocks, so its rank
	// must be split: whatever it owned strictly before pos stays with it,
	// and the rest (if any) transfers to the new node, which now sits
	// between them.
	var below *slNode
	for lvl := range h {
		before := pos - 1 - passedAt[lvl]
		after := preds[lvl].rank - before

		nn := &slNode{level: lvl, rank: 1 + after, down: below, left: preds[lvl]}
		if lvl == 0 {
			nn.tag = tagBytes
		}
		if below != nil {
			below.up = nn
		}
		nn.right = preds[lvl].right
		preds[lvl].right = nn
		if nn.right != nil {
			nn.right.left = nn
		}
		preds[lvl].rank = before
		below = nn
	}
	// Levels ≥ h: no splice, but the block is now inside preds[lvl]'s span.
	for lvl := h; lvl < len(sl.levels); lvl++ {
		preds[lvl].rank++
	}

	sl.n++
	return nil
}

// modifyAt is Algorithm 3 line 10, "replace with T the i-th element of the
// skip list": it replaces the tag of the block at 1-indexed position pos.
func (sl *SkipList) modifyAt(s *suite.Suite, pk *pdp.PublicKey, pos int, block []byte) error {
	target, err := sl.locateNode(pos)
	if err != nil {
		return fmt.Errorf("erway.modifyAt: %w", err)
	}
	target.tag = BlockTag(s, pk, block).Bytes()
	return nil
}

// deleteAt is Algorithm 3 line 12, "delete the i-th element of the skip
// list": at every level the block's own tower reaches, it splices the
// block out (mirroring doInsert's splice); at every level above that, it
// decrements the absorbing predecessor's rank (mirroring doInsert's rank
// bump for levels ≥ h).
func (sl *SkipList) deleteAt(pos int) error {
	target, err := sl.locateNode(pos)
	if err != nil {
		return fmt.Errorf("erway.deleteAt: %w", err)
	}

	preds, _ := sl.findPreds(pos) // predecessor at every level, i.e. the splice/rank-adjust point

	towerNode := target // the deleted block's own node at the level just confirmed
	stillTower := true
	for lvl := 0; lvl < len(sl.levels); lvl++ {
		p := preds[lvl]
		isT := stillTower
		if isT {
			if lvl == 0 {
				isT = p.right == target
			} else {
				isT = p.right != nil && p.right.down == towerNode
			}
		}
		if isT {
			removed := p.right
			p.right = removed.right
			if p.right != nil {
				p.right.left = p
			}
			// removed.rank counted the deleted block itself (1) plus
			// anything else absorbed into it by later inserts at levels
			// below this one; that absorbed remainder now belongs to p,
			// which inherits removed's former span.
			if removed.rank > 1 {
				p.rank += removed.rank - 1
			}
			towerNode = removed
		} else {
			p.rank--
			stillTower = false
		}
	}

	sl.n--
	return nil
}

// ─── atRank ───────────────────────────────────────────────────────────────────

// ProofStep is this package's version of Algorithm 1/2's tuple A(v) =
// (l(v), q(v), d(v), g(v)) for one node v of a verification path (§3.2).
// Level is l(v), the node's level. Right is d(v), which of the two
// directions (rgt/dwn) the path came from. SibLabel is g(v), the sibling
// value needed to fold past v without recursing into it. Rank plays q(v)'s
// role, carrying the rank/count information the fold needs to reconstruct
// both the label and the queried position, but its case split is specific
// to f's tower/plateau formula (see f's doc) rather than a transcription of
// q(v)'s own case split, which is specific to Definition 3's unconditional
// h(level, rank, down, right) labeling.
//
//   - Right: true if the traversal moved right from this node (this node is
//     strictly left of the target and is being folded past); false if the
//     traversal descended from this node (this node is an ancestor whose
//     span contains the target).
//   - TowerPassthrough: only meaningful when Right is false. True when this
//     node's right neighbour is a tower node (also present one level up).
//     Per f's case 2(a), this node's label is then exactly its down value,
//     unchanged, and Level/Rank/SibLabel carry no information: the node's
//     rank is understood to equal its down neighbour's rank rather than
//     separately claimed.
type ProofStep struct {
	Level            int
	Rank             int
	Right            bool
	TowerPassthrough bool
	SibLabel         []byte
}

// BlockProof is this package's Π(i), the proof for block i returned by
// atRank (Algorithm 1: "return representation T of block i and proof
// Π = (A(v1), A(v2), . . . , A(vk)) for T", §3.2). Target is T(mi) itself,
// where this package's zeroEntry carries the block's rank alongside its
// tag. Steps is the (A(v1), . . . , A(vk)) sequence, one ProofStep per node
// of the verification path. TargetRightVal is the value needed to fold in
// the target's own right neighbour (that neighbour's raw entry if it's a
// tower node, or its recursive label if it's a plateau node, exactly as f
// would choose for any other level-0 node): it's needed because, unlike
// every other node on the path, the target has no ProofStep of its own to
// carry it.
//
// TargetIsTower records whether the target itself is a tower node. Regular
// verification (verifyPath) doesn't need it, since the fold already
// accounts for everything transitively. Re-deriving a Modify's effect on
// the basis does need it: per f's level-0 formula, a tower's *left*
// neighbour hashes in the tower's raw entry directly rather than a
// recursive label, so that neighbour's own label, and everything folded
// through it, depends on the target's raw bytes too. VerifyUpdate's
// OpModify case resolves this using a second, independent atInsertionPoint
// proof rather than patching the affected step in this proof directly: the
// affected value can sit underneath other, unrelated hashing along the
// way (e.g. an off-path sibling one level up), so it isn't recoverable
// from already-hashed data here.
type BlockProof struct {
	Target         zeroEntry
	TargetRightVal []byte
	TargetIsTower  bool
	Steps          []ProofStep
}

// atRank is Algorithm 1 (§3.2): "Let v1, v2, . . . , vk be the verification
// path for block i; return representation T of block i and proof
// Π = (A(v1), A(v2), . . . , A(vk)) for T." It traverses to the data block
// at 1-indexed position pos and returns the verification path (BlockProof,
// this package's Π) for it.
func (sl *SkipList) atRank(pos int) (BlockProof, error) {
	if pos < 1 || pos > sl.n {
		return BlockProof{}, fmt.Errorf("erway.atRank: pos=%d out of range [1,%d]", pos, sl.n)
	}

	type entry struct {
		node      *slNode
		wentRight bool
	}
	var path []entry

	v := sl.levels[len(sl.levels)-1]
	passed := 0

	for v.down != nil || v.level > 0 {
		w := v.right
		if w != nil && !w.isSentinel && pos > passed+v.rank {
			path = append(path, entry{v, true})
			passed += v.rank
			v = w
			continue
		}
		if v.down != nil {
			path = append(path, entry{v, false})
			v = v.down
			continue
		}
		break
	}

	// v is now a level-0 node. Scan right until reaching pos, recording each
	// intermediate hop as a "went right" step exactly like higher levels.
	// Per f's tower/plateau invariant, none of these hops can land on a
	// tower node: if the next element were also present one level up, the
	// traversal above would already have taken it, since it would have
	// been visible, and reachable if warranted, from there. So every one
	// of them is folded via the ordinary plateau formula.
	for {
		if !v.isSentinel && passed+1 == pos {
			break
		}
		path = append(path, entry{v, true})
		if !v.isSentinel {
			passed++
		}
		v = v.right
		if v == nil {
			return BlockProof{}, fmt.Errorf("erway.atRank: pos=%d walked off the end of level 0", pos)
		}
	}
	target := zeroEntryOf(v)
	targetRightVal := rightValFor(v)
	targetIsTower := isTower(v)

	var steps []ProofStep
	for i := len(path) - 1; i >= 0; i-- {
		e := path[i]
		node := e.node
		var step ProofStep
		step.Level = node.level
		step.Rank = node.rank
		if e.wentRight {
			step.Right = true
			step.SibLabel = downValueFor(node)
		} else {
			step.Right = false
			w := node.right
			if isTower(w) {
				step.TowerPassthrough = true
			} else {
				step.SibLabel = f(w)
			}
		}
		steps = append(steps, step)
	}

	return BlockProof{
		Target:         target,
		TargetRightVal: targetRightVal,
		TargetIsTower:  targetIsTower,
		Steps:          steps,
	}, nil
}

// downValueFor returns the value a proof step reveals for a node v that a
// search path passes rightward through (see atRank/atInsertionPoint): v's
// own elem(v) at level 0, or f(v.down) at level ≥1, whichever argument f's
// own down-side case (1 vs 2) would use for v. This plays the same role as
// λ(vi) in Papamanthou-Tamassia's Definition 4 (Proof Path, §3.1): the
// value a proof reveals for an off-path node so the verifier can fold past
// it without recursing into its own subtree. It also carries f's
// tower/plateau distinction, used together with rightValFor by
// atRank/atInsertionPoint's step construction.
func downValueFor(v *slNode) []byte {
	if v.level == 0 {
		return elem(v)
	}
	return f(v.down)
}

// rightValFor returns the value a level-0 node v combines with elem(v) to
// form f(v): elem(w) if w = right(v) is a tower node (f's case 1(a)), or
// f(w) if w is a plateau node (case 1(b)). It's used for a proof's Target,
// the level-0 end of a search path, the same way downValueFor is used for
// every other node the path passes.
func rightValFor(v *slNode) []byte {
	w := v.right
	if w == nil {
		return nullLabel
	}
	if isTower(w) {
		return elem(w)
	}
	return f(w)
}

// ─── Verify (client) ─────────────────────────────────────────────────────────

// reconstructRoot is this package's version of the γ_j computation in
// Algorithm 2's for-loop (§3.3: "γj = h(λj , ρj , γj−1 , gj )" going right,
// "γj = h(λj , ρj , gj , γj−1 )" going down): the fold that turns a
// verification path back into a start-node label, γ_k, without yet
// comparing it to anything. It folds a BlockProof into a root label. Two
// things differ from Algorithm 2's own version, both consequences of using
// f in place of Definition 3 (see f's doc): the level-0 base case, and the
// TowerPassthrough steps that skip the hash entirely. Case 2(a) of f is not
// a hash at all, so there is nothing for the paper's γj formula to compute
// there; gamma is simply carried through unchanged.
func reconstructRoot(bp BlockProof) []byte {
	gamma := nodeHash(bp.Target.bytes(), bp.TargetRightVal)

	var lEnc, rEnc [8]byte
	for _, step := range bp.Steps {
		if !step.Right && step.TowerPassthrough {
			continue // gamma unchanged: this level's label is exactly its down value
		}
		if step.Level == 0 {
			if step.Right {
				gamma = nodeHash(step.SibLabel, gamma)
			} else {
				gamma = nodeHash(gamma, step.SibLabel)
			}
			continue
		}
		binary.BigEndian.PutUint64(lEnc[:], uint64(step.Level))
		binary.BigEndian.PutUint64(rEnc[:], uint64(step.Rank))
		if step.Right {
			gamma = nodeHash(lEnc[:], rEnc[:], step.SibLabel, gamma)
		} else {
			gamma = nodeHash(lEnc[:], rEnc[:], gamma, step.SibLabel)
		}
	}
	return gamma
}

// foldOwnTower has no counterpart in any of the three papers. It exists
// only because of a consequence of f's tower/plateau labeling that none of
// them need to deal with: a Modify can change what a node *other than the
// target* folds to, if that node treats the target as a tower neighbour
// (see BlockProof's TargetIsTower doc). It folds targetBytes (in place of
// bp.Target.bytes(), so this can be evaluated for a hypothetical new tag
// too) and bp.TargetRightVal through bp's own leading wentDown steps only,
// stopping before the first wentRight step. The result is the label of the
// target's own top-level counterpart, exactly the value needed wherever
// something one level above the target's own tower folds it in (see
// VerifyUpdate's OpModify tower case). Every step up to that point is
// wentDown by construction, since atRank never needs to go right while
// still descending through the target's own tower: the target's position
// already matches exactly at every one of those levels.
func foldOwnTower(bp BlockProof, targetBytes []byte) []byte {
	gamma := nodeHash(targetBytes, bp.TargetRightVal)
	var lEnc, rEnc [8]byte
	for _, step := range bp.Steps {
		if step.Right {
			break
		}
		if step.TowerPassthrough {
			continue
		}
		binary.BigEndian.PutUint64(lEnc[:], uint64(step.Level))
		binary.BigEndian.PutUint64(rEnc[:], uint64(step.Rank))
		gamma = nodeHash(lEnc[:], rEnc[:], gamma, step.SibLabel)
	}
	return gamma
}

// verifyPath is Algorithm 2, verify(i, Mc, T, Π) (§3.3): it reconstructs
// the root label from a BlockProof (via reconstructRoot, this package's
// γ_k) and compares it to basis (Mc), then checks the block's position.
// This plays the same role as the paper's own "ρk − ξk ≠ i" rejection
// condition (line 15), adapted to this package's rank bookkeeping (see
// ProofStep's doc): the target contributes 1 (if a real block) plus the
// sum of Rank over right-going steps must equal pos. TowerPassthrough
// steps contribute nothing to either the fold or the position sum (their
// rank is inherited from below,
// already counted there).
func verifyPath(basis Basis, pos int, bp BlockProof) (bool, error) {
	if bp.Target.Rank != 1 {
		return false, nil // the target must be a real data entry, not a sentinel
	}
	gamma := reconstructRoot(bp)
	if !equal32(gamma, []byte(basis)) {
		return false, nil
	}

	posCheck := bp.Target.Rank
	for _, step := range bp.Steps {
		if step.Right {
			posCheck += step.Rank
		}
	}
	return posCheck == pos, nil
}

// ─── Challenge, Prove, Verify ───────────────────────────────────────────

// Challenge is this package's version of §4.1's Challenge(sk, pk, Mc) → {c}
// output: "The procedure creates C random block IDs between 1, . . . , n.
// This set of C random block IDs [is] denoted with c." Coeffs are the
// random aⱼ values from §4.2's blockless verification ("aj are random
// values sent by the client as part of the challenge").
type Challenge struct {
	Indices []int      // 1-indexed block positions, len C
	Coeffs  []*big.Int // random coefficients aⱼ, len C
	N       int        // block count at challenge time
}

// MakeChallenge is §4.1's Challenge(sk, pk, Mc) → {c} procedure: it
// generates a fresh Challenge for c blocks out of n.
func MakeChallenge(n, c int) (*Challenge, error) {
	if n <= 0 || c <= 0 {
		return nil, fmt.Errorf("erway.MakeChallenge: n=%d, c=%d must both be positive", n, c)
	}
	if c > n {
		c = n
	}
	perm := make([]int, n)
	for i := range n {
		perm[i] = i + 1
	}
	for i := range c {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(n-i)))
		if err != nil {
			return nil, fmt.Errorf("erway.MakeChallenge: index %d: %w", i, err)
		}
		j := i + int(jBig.Int64())
		perm[i], perm[j] = perm[j], perm[i]
	}
	indices := make([]int, c)
	copy(indices, perm[:c])

	coeffs := make([]*big.Int, c)
	for i := range c {
		a, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, fmt.Errorf("erway.MakeChallenge: coeff %d: %w", i, err)
		}
		coeffs[i] = a
	}
	return &Challenge{Indices: indices, Coeffs: coeffs, N: n}, nil
}

// Proof is this package's version of §4.1/§4.2's output P: the C skip-list
// proofs Prove produces by calling atRank (Algorithm 1) once per challenged
// index (Blocks), plus the combined block M from §4.2's blockless
// verification.
type Proof struct {
	Blocks []BlockProof
	M      *big.Int // Σ aⱼ · blockᵢⱼ (as an integer)
}

// Prove is §4.1/§4.2's Prove(pk, Fi, Mi, c) → {P}: "Prove calls Algorithm 1
// C times (with arguments i1, i2, . . . , iC) and sends back C proofs,"
// plus, per §4.2, "the server also sends a combined block
// M = ΣCj=1 aj mij." store is 0-indexed; erway uses 1-indexed positions
// internally, so Block(idx-1) is called.
func Prove(s *suite.Suite, pk *pdp.PublicKey, sl *SkipList, chal *Challenge, store blocks.BlockStore) (*Proof, error) {
	if chal.N != sl.n {
		return nil, fmt.Errorf("erway.Prove: challenge N=%d but skip list n=%d", chal.N, sl.n)
	}

	bps := make([]BlockProof, len(chal.Indices))
	M := big.NewInt(0)

	for t, idx := range chal.Indices {
		bp, err := sl.atRank(idx)
		if err != nil {
			return nil, fmt.Errorf("erway.Prove: atRank(%d): %w", idx, err)
		}
		bps[t] = bp

		block, err := store.Block(blocks.IntID(idx - 1)) // erway uses 1-indexed positions; BlockStore is 0-indexed
		if err != nil {
			return nil, fmt.Errorf("erway.Prove: block %d: %w", idx, err)
		}
		M.Add(M, new(big.Int).Mul(chal.Coeffs[t], new(big.Int).SetBytes(block)))
	}

	return &Proof{Blocks: bps, M: M}, nil
}

// Verify is §4.1/§4.2's Verify(sk, pk, Mc, c, P) → {accept, reject}: it
// "runs Algorithm 2 [verifyPath] using as inputs the indices in c, the
// metadata Mc, the data T and the proof sent by the server," then, per
// §4.2's blockless verification, "accepts if T = g^M mod N and the skip
// list proof verifies" (T there is this function's rhs, computed from the
// tags rather than downloaded blocks).
func Verify(pk *pdp.PublicKey, basis Basis, chal *Challenge, proof *Proof) (bool, error) {
	if len(proof.Blocks) != len(chal.Indices) {
		return false, fmt.Errorf("erway.Verify: proof has %d block proofs, want %d",
			len(proof.Blocks), len(chal.Indices))
	}

	for t, idx := range chal.Indices {
		ok, err := verifyPath(basis, idx, proof.Blocks[t])
		if err != nil {
			return false, fmt.Errorf("erway.Verify: path[%d] (block %d): %w", t, idx, err)
		}
		if !ok {
			return false, nil
		}
	}

	// Blockless verification (§4.2): g^M = ∏ T(blockᵢⱼ)^{aⱼ} mod N.
	rhs := big.NewInt(1)
	for t := range chal.Indices {
		tag := new(big.Int).SetBytes(proof.Blocks[t].Target.Tag)
		term := new(big.Int).Exp(tag, chal.Coeffs[t], pk.N)
		rhs.Mul(rhs, term)
		rhs.Mod(rhs, pk.N)
	}
	lhs := new(big.Int).Exp(pk.G, proof.M, pk.N)

	return lhs.Cmp(rhs) == 0, nil
}

// ─── Updates (§3.4) ───────────────────────────────────────────────────────────

// OpKind is Algorithm 3/4's upd parameter: "if upd is a deletion... else
// {upd is an insertion or modification}" (§3.4).
type OpKind int

const (
	OpModify OpKind = iota
	OpInsert
	OpDelete
)

// UpdateOp is this package's version of Algorithm 3's own input tuple
// (i, T, upd): Pos is i, Block is T, Kind is upd, plus Height (see below;
// the paper's own upd for an insertion "include[s] the tower height,"
// §3.4, but the paper doesn't itself name a field for it). Height is the
// tower height of the block involved: for OpInsert, the new block's
// height, chosen by the caller (e.g. via ChooseHeight); for OpDelete, the
// height the caller originally chose when that block was inserted. Both
// must come from the caller, not the server, per §3.4 ("the client
// decides the height of the tower"), so a lying server's claim simply
// fails VerifyUpdate. For OpDelete specifically, an honest server can't
// even produce a passing proof for a dishonest height, since the
// delete-via-reinsertion check (see VerifyUpdate's OpDelete case)
// reproduces oldBasis only when Height is exactly right.
type UpdateOp struct {
	Kind   OpKind
	Pos    int // 1-indexed position
	Block  []byte
	Height int // OpInsert, OpDelete
}

// UpdateResult is this package's version of Algorithm 3's output pair
// (T', Π'): the pre-update proof(s) the client needs to verify the
// operation and derive the new basis for itself. This package's own
// tower/plateau labeling (§4.2 of Goodrich-Tamassia-Schwerin, used in
// place of Erway's own Definition 3) needs at most two proofs for
// anything beyond a single atRank query, rather than the paper's single
// Π'; see each case below and BlockProof's TargetIsTower doc.
//
//   - OpModify: Proof is the target's own pre-update atRank proof.
//     LeftProof is populated only when Proof.TargetIsTower; see
//     BlockProof's doc and VerifyUpdate's OpModify case for why.
//   - OpInsert: Proof is the insertion-point proof (atInsertionPoint),
//     taken before the insert.
//   - OpDelete: Proof is the deleted block's own pre-deletion atRank
//     proof (reveals its tag, authenticated against oldBasis). PostProof
//     is the insertion-point proof at the same position, taken *after*
//     the deletion; see VerifyUpdate's OpDelete case for how the two are
//     combined (delete-via-reinsertion).
type UpdateResult struct {
	Proof     BlockProof
	LeftProof *BlockProof
	PostProof *BlockProof
}

// PerformUpdate is this package's version of Algorithm 3,
// performUpdate(i, T, upd) → (T', Π') (§3.4), with one significant
// departure for OpDelete (see below). For OpModify and OpInsert it follows
// the paper directly: "set (T', Π') = atRank(j)" (line 6; atRank(op.Pos)
// itself for Modify, and atInsertionPoint(op.Pos), this package's closest
// equivalent for a not-yet-existing position, for Insert), then the update
// itself (lines 7-9/10: modifyAt/doInsert), then "update the labels,
// levels and ranks of the affected nodes" (line 14, automatic here since f
// is never cached).
//
// For OpDelete, this package follows Papamanthou-Tamassia's §3.2 "reduce
// an authenticated deletion to an authenticated insertion" instead: it
// deletes first, then proves the resulting *gap*, rather than Algorithm
// 3's own line 2 (j = i - 1, prove the predecessor first). See
// VerifyUpdate's OpDelete case for why, and for the rest of that
// technique's port.
func (sl *SkipList) PerformUpdate(s *suite.Suite, pk *pdp.PublicKey, op UpdateOp) (*UpdateResult, error) {
	switch op.Kind {
	case OpModify:
		proof, err := sl.atRank(op.Pos)
		if err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		var leftProof *BlockProof
		if proof.TargetIsTower {
			lp, _, err := sl.atInsertionPoint(op.Pos)
			if err != nil {
				return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
			}
			leftProof = &lp
		}
		if err := sl.modifyAt(s, pk, op.Pos, op.Block); err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		return &UpdateResult{Proof: proof, LeftProof: leftProof}, nil

	case OpInsert:
		if op.Height < 1 {
			return nil, fmt.Errorf("erway.PerformUpdate: insert height must be >= 1")
		}
		proof, _, err := sl.atInsertionPoint(op.Pos)
		if err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		if err := sl.doInsert(s, pk, op.Pos, op.Block, op.Height); err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		sl.heights = append(sl.heights, 0)
		copy(sl.heights[op.Pos:], sl.heights[op.Pos-1:len(sl.heights)-1])
		sl.heights[op.Pos-1] = op.Height
		return &UpdateResult{Proof: proof}, nil

	case OpDelete:
		// Papamanthou-Tamassia's delete(x) (§3.2) already knows x, since a
		// key-based dictionary's caller names the element to remove
		// directly. This package's blocks are identified by position, not
		// value, so the tag being deleted isn't known up front. atRank
		// here authenticates it against the pre-deletion basis before
		// deleteAt removes it, so it's available afterward as VerifyUpdate
		// input.
		proof, err := sl.atRank(op.Pos)
		if err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		if err := sl.deleteAt(op.Pos); err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		// "constructs a proof π' by issuing a contains(x) query" (§3.2).
		// This package's non-membership analogue, atInsertionPoint, proves
		// the gap left behind.
		postProof, _, err := sl.atInsertionPoint(op.Pos)
		if err != nil {
			return nil, fmt.Errorf("erway.PerformUpdate: %w", err)
		}
		if op.Pos-1 < len(sl.heights) {
			sl.heights = append(sl.heights[:op.Pos-1], sl.heights[op.Pos:]...)
		}
		return &UpdateResult{Proof: proof, PostProof: &postProof}, nil

	default:
		return nil, fmt.Errorf("erway.PerformUpdate: unknown op kind %d", op.Kind)
	}
}

// VerifyUpdate is this package's version of Algorithm 4,
// verUpdate(i, Mc, T, upd, T', Π') → {accept, reject} (§3.4): "if
// verify(j, Mc, T', Π') = reject then return reject; else... from i, T, T',
// and Π', compute and store the updated label Mc' of the start node." The
// returned basis is always derived locally from result's proof(s), never
// trusted from any server-claimed value, which is the fix for this
// package's original soundness gap (see the package doc). The paper's own
// verUpdate already has this property: it computes Mc' itself, in line 8,
// rather than accepting a claimed one. So this function's fix is simply
// bringing this package in line with Algorithm 4, not a deviation from it.
func VerifyUpdate(s *suite.Suite, pk *pdp.PublicKey, oldBasis Basis, op UpdateOp, result *UpdateResult) (Basis, bool, error) {
	switch op.Kind {
	case OpModify:
		// Deriving the new basis from a verified atRank proof (Algorithm
		// 4's own "from i, T, T', and Π', compute... Mc'") has no
		// off-the-shelf recipe in any of the three papers: Definition 3's
		// chained labeling makes a bounded derivation impossible in the
		// first place (see the package doc), and neither of the other two
		// papers' own schemes have this package's tower/plateau split, so
		// neither needs to worry about the target's raw bytes leaking into
		// a neighbour's label the way BlockProof's TargetIsTower doc
		// describes. Both branches below are this package's own solution
		// to that split, not a port of anything.
		ok, err := verifyPath(oldBasis, op.Pos, result.Proof)
		if err != nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: %w", err)
		}
		if !ok {
			return nil, false, nil
		}
		newTag := BlockTag(s, pk, op.Block).Bytes()

		if !result.Proof.TargetIsTower {
			// Plateau case: the target's own label is a straightforward
			// recursive fold (see the package doc), so its own proof
			// already carries everything needed. Just swap the tag.
			newProof := result.Proof
			newProof.Target.Tag = newTag
			return Basis(reconstructRoot(newProof)), true, nil
		}

		// Tower case: the target's immediate level-0 left neighbour hashes
		// in the target's raw entry directly rather than a recursive label
		// (see BlockProof's doc), so that neighbour's own label depends on
		// the target's raw bytes. Separately, the left neighbour's ancestor
		// chain has exactly one more dependency on the target. At every
		// level below the target's own height, nothing can sit between the
		// left neighbour and the target: they're adjacent at level 0, and a
		// higher-level node always projects to a level-0 position, so
		// nothing can wedge between them at any level either. This means
		// the target's own counterpart is always that ancestor's immediate
		// right neighbour there too, either pass-through (still inside the
		// target's own tower) or, at exactly the level the target's tower
		// stops, a direct hash of the target's own top-level label
		// (foldOwnTower below computes this properly, folding in whatever's
		// to that top node's own right, rather than just returning the
		// level-0 label directly). These values can sit underneath other,
		// unrelated hashing along the way, so they aren't recoverable by
		// patching result.Proof directly; instead use a second, independent
		// proof of the left neighbour itself: atInsertionPoint(op.Pos)
		// finds exactly that neighbour, and works even if it's a sentinel.
		if result.LeftProof == nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: proof claims a tower target but LeftProof is missing")
		}
		ok, err = verifyInsertionPoint(oldBasis, op.Pos, *result.LeftProof)
		if err != nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: %w", err)
		}
		if !ok {
			return nil, false, nil
		}
		oldTargetBytes := result.Proof.Target.bytes()
		newTargetBytes := zeroEntry{Rank: 1, Tag: newTag}.bytes()
		if !equal32(result.LeftProof.TargetRightVal, oldTargetBytes) {
			return nil, false, nil
		}
		fTargetTopOld := foldOwnTower(result.Proof, oldTargetBytes)
		fTargetTopNew := foldOwnTower(result.Proof, newTargetBytes)

		newLeftProof := *result.LeftProof
		newLeftProof.Steps = append([]ProofStep{}, result.LeftProof.Steps...)
		newLeftProof.TargetRightVal = newTargetBytes

		idx := -1
		for i, st := range newLeftProof.Steps {
			if !st.Right && !st.TowerPassthrough {
				idx = i
				break
			}
		}
		if idx >= 0 {
			if !equal32(newLeftProof.Steps[idx].SibLabel, fTargetTopOld) {
				return nil, false, nil
			}
			newLeftProof.Steps[idx].SibLabel = fTargetTopNew
		}
		return Basis(reconstructRoot(newLeftProof)), true, nil

	case OpInsert:
		// Conceptually this is Figure 2's update(Q, ℓ, x, t), the
		// insertion half of the digest-update algorithm both Erway's own
		// §3.4 and Papamanthou-Tamassia's paper describe. Figure 2 is
		// written for Definition 1's sequential hashing S(), which this
		// package's f (see its doc) does not use. deriveBasisAfterInsert
		// below re-derives the equivalent fold from scratch, directly
		// against the tower/plateau formula.
		if op.Height < 1 {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: insert height must be >= 1")
		}
		ok, err := verifyInsertionPoint(oldBasis, op.Pos, result.Proof)
		if err != nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: %w", err)
		}
		if !ok {
			return nil, false, nil
		}
		newTag := BlockTag(s, pk, op.Block).Bytes()
		return Basis(deriveBasisAfterInsert(result.Proof, op.Pos, op.Height, newTag)), true, nil

	case OpDelete:
		// This is Papamanthou-Tamassia §3.2's "reduce an authenticated
		// deletion to an authenticated insertion" ported directly: "The
		// client runs the update algorithm on input π', x, ℓ. If the
		// output digest is s, then the deletion is accepted and the new
		// digest is s' = S(π')." result.Proof authenticates the deleted
		// block (its tag, this package's x) against oldBasis (s).
		// result.PostProof is π', an insertion-point proof at the same
		// position taken from the tree *after* the deletion (the
		// non-membership proof their contains(x) query would return).
		// op.Height is ℓ. Running deriveBasisAfterInsert (this package's
		// update()) on (π', x, ℓ) must reproduce oldBasis (s) exactly.
		// That's only possible if PostProof genuinely represents the old
		// tree with this one block removed, since deriveBasisAfterInsert's
		// fold is collision-resistant in every value it depends on. Once
		// that holds, PostProof's own fold is simply the new basis
		// (S(π')), no further computation needed.
		if op.Height < 1 {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: delete height must be >= 1")
		}
		if result.PostProof == nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: delete result missing PostProof")
		}
		ok, err := verifyPath(oldBasis, op.Pos, result.Proof)
		if err != nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: %w", err)
		}
		if !ok {
			return nil, false, nil
		}
		reinserted := deriveBasisAfterInsert(*result.PostProof, op.Pos, op.Height, result.Proof.Target.Tag)
		if !equal32(reinserted, []byte(oldBasis)) {
			return nil, false, nil
		}
		return Basis(reconstructRoot(*result.PostProof)), true, nil

	default:
		return nil, false, fmt.Errorf("erway.VerifyUpdate: unknown op kind %d", op.Kind)
	}
}

// deriveBasisAfterInsert is this package's update(). It plays exactly the
// role Figure 2's algorithm of that name plays for Papamanthou-Tamassia's
// sequential-hash scheme, though it isn't a port of it: Figure 2 processes
// an extended proof path Q(x) by sequentially hashing S(), which has no
// tower/plateau distinction to worry about, so its case split (§3.2's
// ℓ == 0 vs ℓ > 0, and the loop building L/R/U) doesn't carry over. This
// re-derives the equivalent fold from scratch: it locally recomputes the
// post-insert basis from a verified atInsertionPoint proof taken
// immediately before the insert, by replaying doInsert's own
// rank-splitting arithmetic against f (see its doc). pos is the 1-indexed
// insertion position; h is the client-chosen tower height (§3.4); tagBytes
// is the new block's tag.
//
// Off-path values (every wentRight step's SibLabel, and every wentDown
// step's SibLabel/TowerPassthrough at a level the new tower doesn't reach,
// level >= h) are provably unaffected by the insert, since they describe
// subtrees strictly left of, or entirely disjoint from, the splice point,
// so they're reused exactly as revealed. Only the on-path chain (levels <
// h) is recomputed: each such level's predecessor splits into a shrunk
// predecessor plus a new tower node, and a second, parallel fold tracks the
// new tower's own label level by level, since it becomes the down value for
// the next level of the new tower.
func deriveBasisAfterInsert(proof BlockProof, pos, h int, tagBytes []byte) []byte {
	fold := func(level, rank int, a, b []byte) []byte {
		var lEnc, rEnc [8]byte
		binary.BigEndian.PutUint64(lEnc[:], uint64(level))
		binary.BigEndian.PutUint64(rEnc[:], uint64(rank))
		return nodeHash(lEnc[:], rEnc[:], a, b)
	}
	// passedAt, for level L, is recovered from the proof itself: the sum
	// of every wentRight step's rank at level >= L (matching findPreds'
	// own running total, which never resets between levels).
	passedAt := func(level int) int {
		total := 0
		for _, st := range proof.Steps {
			if st.Right && st.Level >= level {
				total += st.Rank
			}
		}
		return total
	}

	// Level 0: proof.Target always ends exactly at pos-1 (level-0 ranks
	// are 0 or 1, so there's nothing to split off); only its right
	// neighbour changes, from whatever it used to be to the new node.
	newElem := zeroEntry{Rank: 1, Tag: tagBytes}
	newNodeGamma := nodeHash(newElem.bytes(), proof.TargetRightVal) // f(new node), level 0

	var predsRight []byte
	if h >= 2 {
		predsRight = newElem.bytes() // new node is a tower from level 0's own perspective
	} else {
		predsRight = newNodeGamma
	}
	gamma := nodeHash(proof.Target.bytes(), predsRight) // new f(preds[0])

	for _, step := range proof.Steps {
		if step.Right {
			if step.Level == 0 {
				gamma = nodeHash(step.SibLabel, gamma)
			} else {
				gamma = fold(step.Level, step.Rank, step.SibLabel, gamma)
			}
			continue
		}
		L := step.Level
		if L >= h {
			if !step.TowerPassthrough {
				gamma = fold(L, step.Rank+1, gamma, step.SibLabel)
			}
			continue
		}
		before := pos - 1 - passedAt(L)
		after := step.Rank - before
		newRank := 1 + after

		var newNodeGammaL []byte
		if step.TowerPassthrough {
			newNodeGammaL = newNodeGamma
		} else {
			newNodeGammaL = fold(L, newRank, newNodeGamma, step.SibLabel)
		}
		if L == h-1 {
			gamma = fold(L, before, gamma, newNodeGammaL)
		} // else: the new node is itself a tower here too, so preds[L]'s
		// label is a pure pass-through of gamma, already unchanged.
		newNodeGamma = newNodeGammaL
	}

	return gamma
}
