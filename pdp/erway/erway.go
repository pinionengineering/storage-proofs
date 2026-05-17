// Package erway implements Dynamic Provable Data Possession I (DPDP I) from
// "Dynamic Provable Data Possession" by Erway, Küpçü, Papamanthou, and Tamassia
// (ACM CCS 2009). A copy of the paper is in doc/dynamic-provable-data-possession.pdf.
//
// # Overview
//
// DPDP I extends static PDP to support provable updates (insert, modify, delete)
// on the outsourced file. The server maintains a rank-based authenticated skip
// list whose leaves hold block tags T(b) = g^{SHA-256(b)} mod N. The client
// retains only a single 32-byte "basis" — the hash label of the skip list's
// start (top-left) node — as O(1) metadata (§4, Theorem 1).
//
// The key differences from Ateniese S-PDP:
//   - No secret key: tags T(b) = g^b mod N are publicly computable; security
//     rests on the factoring assumption plus collision resistance of the skip
//     list hash function (§5, Theorem 2).
//   - O(log n) proof size per challenged block: each block requires a skip-list
//     path proof in addition to the aggregated sum M (§4.2, Figure 3).
//   - Dynamic updates: Insert, Modify, Delete all run in expected O(log n) time
//     and produce a basis update the client can verify from O(log n) data (§3.4).
//
// # Hashing convention (§3.1, Definition 3)
//
// The multi-argument hash is h(x₁,…,xₖ) = SHA-256(SHA-256(x₁)‖…‖SHA-256(xₖ)).
// Integer arguments (level, rank) are encoded as big-endian uint64.
//
// Label of a node v:
//
//	f(null)       = 0³²
//	f(v), l(v)=0  = h(l(v), r(v), T(block_v), f(rgt(v)))          [bottom level]
//	f(v), l(v)>0  = h(l(v), r(v), f(dwn(v)),  f(rgt(v)))          [internal]
//
// The rank r(v) counts data blocks in v's "responsibility range" at level 0.
// For a non-sentinel bottom-level node v, r(v) = 1.
// For an internal node v, r(v) = number of bottom-level data nodes from v's
// bottom projection (inclusive) up to, but not including, the bottom projection
// of rgt(v) at the same level.
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

// BlockTag computes T(b) = g^{s.HashBlock(b)} mod N for block data b (§4.2).
// Note: the paper defines T(b) = g^b mod N, but hashing b as the exponent
// avoids oversized exponents and keeps the scheme secure under the same
// factoring assumption (HashBlock is modelled as a random oracle).
func BlockTag(s *suite.Suite, pk *pdp.PublicKey, block []byte) *big.Int {
	return new(big.Int).Exp(pk.G, s.HashBlock(block), pk.N)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var nullLabel = make([]byte, 32)

// nodeHash implements h(x₁,…,xₖ) = SHA-256(SHA-256(x₁)‖…‖SHA-256(xₖ)) from §3.1.
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

// slNode is one node in the authenticated skip list.
//
// The structure is a standard skip list extended with:
//   - rank: count of data (non-sentinel) nodes between this node and its
//     right neighbour at the same level (inclusive of this node's bottom projection).
//   - label: the 32-byte collision-resistant hash per Definition 3.
//   - tag: T(block).Bytes() for bottom-level data nodes only.
type slNode struct {
	level int
	right *slNode
	down  *slNode
	// rank = number of data blocks "owned" by this node.
	// For a bottom-level data node: rank = 1.
	// For a sentinel: rank is the count of data nodes to the right up to the next
	// node at this level (and down towers below).
	// Maintained by recomputeRanks() after structural changes.
	rank       int
	tag        []byte // non-nil only for level-0 data nodes
	isSentinel bool
	label      []byte // f(v)
}

// recomputeLabel recomputes v.label from its children per Definition 3 (§3.1).
func (v *slNode) recomputeLabel() {
	var lEnc, rEnc [8]byte
	binary.BigEndian.PutUint64(lEnc[:], uint64(v.level))
	binary.BigEndian.PutUint64(rEnc[:], uint64(v.rank))

	tagBytes := v.tag
	if tagBytes == nil {
		tagBytes = nullLabel
	}

	rightLabel := nullLabel
	if v.right != nil {
		rightLabel = v.right.label
		if rightLabel == nil {
			rightLabel = nullLabel
		}
	}
	downLabel := nullLabel
	if v.down != nil {
		downLabel = v.down.label
		if downLabel == nil {
			downLabel = nullLabel
		}
	}

	if v.level == 0 {
		// Case 2 (§3.1 Definition 3): f(v) = h(l(v), r(v), x(v), f(rgt(v)))
		v.label = nodeHash(lEnc[:], rEnc[:], tagBytes, rightLabel)
	} else {
		// Case 1 (§3.1 Definition 3): f(v) = h(l(v), r(v), f(dwn(v)), f(rgt(v)))
		v.label = nodeHash(lEnc[:], rEnc[:], downLabel, rightLabel)
	}
}

// SkipList is the server-side rank-based authenticated skip list (§3).
// Internally it is represented as a flat set of nodes per level, each level
// forming a singly-linked list.
//
// levels[i] is the leftmost (sentinel) node at level i.
// The skip list always has at least 1 level (levels[0]).
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

// Basis is the O(1) client metadata: the 32-byte root label.
type Basis []byte

// Clone returns an independent copy.
func (b Basis) Clone() Basis {
	c := make(Basis, len(b))
	copy(c, b)
	return c
}

// rootLabel returns the label of the topmost-leftmost node (the "start" node).
func (sl *SkipList) rootLabel() []byte {
	top := sl.levels[len(sl.levels)-1]
	if top == nil || top.label == nil {
		return make([]byte, 32)
	}
	return top.label
}

// ─── Build ────────────────────────────────────────────────────────────────────

// Build initialises a SkipList for the given blocks and returns the skip list
// (server) and the initial basis (client).
func Build(s *suite.Suite, pk *pdp.PublicKey, store blocks.BlockStore) (*SkipList, Basis, error) {
	if store.Len() == 0 {
		return nil, nil, fmt.Errorf("erway.Build: blocks must not be empty")
	}

	// Start with one level: two sentinel nodes.
	rightSent := &slNode{level: 0, isSentinel: true}
	leftSent := &slNode{level: 0, isSentinel: true, right: rightSent}
	rightSent.label = make([]byte, 32)
	leftSent.label = make([]byte, 32)

	sl := &SkipList{levels: []*slNode{leftSent}}

	for i := range store.Len() {
		b, err := store.Block(i)
		if err != nil {
			return nil, nil, fmt.Errorf("erway.Build: block %d: %w", i, err)
		}
		if err := sl.appendBlock(s, pk, b); err != nil {
			return nil, nil, fmt.Errorf("erway.Build: block %d: %w", i, err)
		}
	}

	basis := make(Basis, 32)
	copy(basis, sl.rootLabel())
	return sl, basis, nil
}

// coinHeight returns a random tower height using a geometric distribution (p=1/2).
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

// maxHeight computes a sensible height cap.
func (sl *SkipList) maxHeight() int {
	h := 2
	for (1 << h) < sl.n+4 {
		h++
	}
	return h
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

	rightSent := &slNode{level: 0, isSentinel: true}
	leftSent := &slNode{level: 0, isSentinel: true, right: rightSent}
	rightSent.label = make([]byte, 32)
	leftSent.label = make([]byte, 32)

	sl := &SkipList{levels: []*slNode{leftSent}, heights: make([]int, n)}
	copy(sl.heights, heights)

	for i := range n {
		b, err := store.Block(i)
		if err != nil {
			return nil, nil, fmt.Errorf("erway.BuildWithHeights: block %d: %w", i, err)
		}
		if err := sl.doInsert(s, pk, sl.n+1, b, heights[i]); err != nil {
			return nil, nil, fmt.Errorf("erway.BuildWithHeights: block %d: %w", i, err)
		}
	}

	basis := make(Basis, 32)
	copy(basis, sl.rootLabel())
	return sl, basis, nil
}

// doInsert inserts block at 1-indexed position pos with the given tower height h.
// This is the core insert operation; all existing nodes at positions ≥ pos shift right.
func (sl *SkipList) doInsert(s *suite.Suite, pk *pdp.PublicKey, pos int, block []byte, h int) error {
	tagInt := BlockTag(s, pk, block)
	tagBytes := tagInt.Bytes()

	// Grow the skip list to accommodate the new tower height.
	for len(sl.levels) < h {
		newLvl := len(sl.levels)
		// New left sentinel at the top: down points to current top-left.
		prevLeft := sl.levels[newLvl-1]
		// Find the right sentinel at the previous top level.
		prevRight := prevLeft
		for prevRight.right != nil {
			prevRight = prevRight.right
		}
		newRight := &slNode{level: newLvl, isSentinel: true, label: make([]byte, 32)}
		newLeft := &slNode{level: newLvl, isSentinel: true, down: prevLeft, right: newRight}
		sl.levels = append(sl.levels, newLeft)
	}

	// Find the predecessor at each level in [0, h).
	// preds[i] is the last node at level i before the insertion point.
	//
	// Traversal invariant: passed = number of data blocks strictly to the left of v.
	// We go right from v to w when pos > passed + v.rank (the target is beyond v's
	// owned range), adding v.rank to passed. This correctly tracks blocks-to-the-left
	// across level transitions (going down does not change passed).
	preds := make([]*slNode, len(sl.levels))
	{
		v := sl.levels[len(sl.levels)-1]
		passed := 0 // data blocks strictly to the left of v's bottom projection
		for lvl := len(sl.levels) - 1; lvl >= 0; lvl-- {
			// Scan right at this level.
			for {
				w := v.right
				if w == nil || w.isSentinel {
					break
				}
				// Go right from v to w if the insertion point is beyond v's owned range.
				if pos > passed+v.rank {
					passed += v.rank
					v = w
				} else {
					break
				}
			}
			preds[lvl] = v
			// Go down to the next level.
			if lvl > 0 {
				if v.down != nil {
					v = v.down
				} else {
					// v is only present at levels ≥ lvl; use left sentinel at lvl-1.
					v = sl.levels[lvl-1]
				}
			}
		}
	}

	// Build the new tower of h nodes.
	var below *slNode
	for lvl := 0; lvl < h; lvl++ {
		n := &slNode{
			level: lvl,
			rank:  1,
			down:  below,
		}
		if lvl == 0 {
			n.tag = tagBytes
		}
		// Splice into the level list after preds[lvl].
		n.right = preds[lvl].right
		preds[lvl].right = n
		below = n
	}

	sl.n++
	sl.recomputeRanks()
	sl.recomputeLabels()
	return nil
}

// recomputeRanks recomputes all rank values from scratch.
// rank of a node v at level l = number of data (non-sentinel) nodes in
// the interval [v's position, next node at level l's position) at level 0.
//
// We compute this as follows:
//  1. For each level, walk the level list and compute spans via the down links.
//     The rank of v = the count of bottom-level data nodes from v's bottom projection
//     up to (but not including) the bottom projection of v.right.
func (sl *SkipList) recomputeRanks() {
	// First, give every bottom-level data node rank 1.
	for v := sl.levels[0]; v != nil; v = v.right {
		if !v.isSentinel {
			v.rank = 1
		} else {
			v.rank = 0
		}
	}

	// For each level > 0, compute ranks by counting bottom-level nodes below.
	for lvl := 1; lvl < len(sl.levels); lvl++ {
		for v := sl.levels[lvl]; v != nil; v = v.right {
			v.rank = 0
			// Count ranks of nodes at level lvl-1 that are "under" v (between v and v.right).
			// The nodes under v at level lvl-1 are: from v.down (inclusive) to
			// (v.right.down if v.right is non-nil and non-sentinel, else end).
			if v.down == nil {
				continue
			}
			// Walk level lvl-1 from v.down until we would reach v.right.down or end.
			var stop *slNode
			if v.right != nil {
				stop = v.right.down
			}
			for w := v.down; w != nil && w != stop; w = w.right {
				v.rank += w.rank
			}
		}
	}
}

// recomputeLabels recomputes all node labels bottom-up and right-to-left.
//
// The label of a node depends on f(v.right) and f(v.down), so we must
// process each level right-to-left (so that v.right's label is already
// current when we compute v.label). Levels are processed bottom-to-top
// (so that v.down's label is current when we compute internal node labels).
func (sl *SkipList) recomputeLabels() {
	for lvl := 0; lvl < len(sl.levels); lvl++ {
		// Collect nodes at this level into a slice for right-to-left traversal.
		var nodes []*slNode
		for v := sl.levels[lvl]; v != nil; v = v.right {
			nodes = append(nodes, v)
		}
		// Process right-to-left so f(v.right) is already up-to-date.
		for i := len(nodes) - 1; i >= 0; i-- {
			nodes[i].recomputeLabel()
		}
	}
}

// ─── atRank ───────────────────────────────────────────────────────────────────

// ProofStep is one element A(vⱼ) = (l(vⱼ), q(vⱼ), d(vⱼ), g(vⱼ)) of the
// verification path Π(i) produced by atRank (§3.2).
//
// Each step reconstructs f(vⱼ) bottom-up per Definition 3 (§3.1, Algorithm 2 §3.3):
//
//   - step 0 (leaf, l=0):           gamma = h(0, Rank, Tag, SibLabel)
//   - step i>0, Right, l=0:         gamma = h(0, Rank, SibLabel, gamma)  [x(v), f(rgt)]
//   - step i>0, Right, l>0:         gamma = h(Level, Rank, SibLabel, gamma) [f(dwn), f(rgt)]
//   - step i>0, !Right (d=dwn), l>0: gamma = h(Level, Rank, gamma, SibLabel) [f(dwn), f(rgt)]
//
// Right (d(vⱼ)) is true when the previous path node is rgt(vⱼ).
// SibLabel is g(vⱼ): label of the off-path child.
// Rank is r(vⱼ): stored rank of this node.
// Q is q(vⱼ): rank of the off-path sibling, used by Algorithm 2's ρ/ξ accumulators.
type ProofStep struct {
	Level    int
	Rank     int    // r(vⱼ): stored rank of this node
	Right    bool   // d(vⱼ): true = previous path node is rgt(vⱼ)
	SibLabel []byte // g(vⱼ): label of the off-path child
	Q        int    // q(vⱼ): rank of the off-path sibling (Algorithm 2, §3.3)
}

// BlockProof is the skip-list proof for one challenged block.
type BlockProof struct {
	Tag   []byte      // T(b).Bytes()
	Steps []ProofStep // verification path, bottom to top
}

// atRank implements Algorithm 1 (§3.2): traverse to the data block at
// 1-indexed position pos and return T(pos) plus the verification path Π(pos).
//
// The traversal follows §3.1: at each node v with accumulated count `passed`,
// go right to rgt(v) when pos > passed+r(v) (adding r(v) to passed), otherwise
// go down. At level 0, walk right until passed+1 == pos. The resulting path
// is reversed to form the bottom-up proof sequence (leaf first, start node last).
func (sl *SkipList) atRank(pos int) (tagBytes []byte, steps []ProofStep, err error) {
	if pos < 1 || pos > sl.n {
		return nil, nil, fmt.Errorf("erway.atRank: pos=%d out of range [1,%d]", pos, sl.n)
	}

	// Forward traversal: record (node, directionTaken) pairs.
	// directionTaken: true = "we moved right from this node", false = "we moved down".
	type entry struct {
		node      *slNode
		wentRight bool
	}
	var path []entry

	v := sl.levels[len(sl.levels)-1]
	passed := 0 // data blocks strictly to the left of v's bottom projection

	for {
		w := v.right
		// Go right from v to w if the target is beyond v's owned range.
		// v owns blocks at positions passed+1 .. passed+v.rank (at level 0).
		// Moving right means the target is at position > passed+v.rank.
		if w != nil && !w.isSentinel && pos > passed+v.rank {
			path = append(path, entry{v, true})
			passed += v.rank
			v = w
		} else if v.down != nil {
			path = append(path, entry{v, false})
			v = v.down
		} else {
			// At level 0 (v.down == nil). v's bottom projection is at passed+1.
			// Advance right to find the target.
			for v != nil {
				if v.isSentinel {
					path = append(path, entry{v, true}) // "went right" from sentinel
					v = v.right
				} else if passed+1 < pos {
					path = append(path, entry{v, true})
					passed++
					v = v.right
				} else {
					// passed+1 == pos: v is the target
					break
				}
			}
			break
		}
	}

	if v == nil || v.isSentinel || v.level != 0 {
		lvl := -1
		if v != nil {
			lvl = v.level
		}
		return nil, nil, fmt.Errorf("erway.atRank: bad traversal pos=%d level=%d sentinel=%v",
			pos, lvl, v == nil || v.isSentinel)
	}
	tagBytes = v.tag

	// Build proof steps bottom-up (reverse of path + leaf step).
	// Step 0 (the leaf): reconstruct f(leaf) = h(0, 1, tag, f(leaf.right)).
	step0 := ProofStep{
		Level:    0,
		Rank:     v.rank, // should be 1
		Right:    true,   // gamma will be combined as: h(level, rank, tag, sib)
		SibLabel: safeLabel(v.right),
		Q:        rankOf(v.right),
	}
	steps = append(steps, step0)

	// Steps 1..n: one per path entry in reverse order.
	for i := len(path) - 1; i >= 0; i-- {
		e := path[i]
		node := e.node

		var step ProofStep
		step.Level = node.level
		step.Rank = node.rank

		if e.wentRight {
			// We moved RIGHT from node to reach the next path entry.
			// gamma is now f(node.right's subtree).
			//
			// At level 0: f(v) = h(0, rank, tag, f(rgt))
			//   gamma = f(rgt). SibLabel = node.tag (data node) or nullLabel (sentinel).
			//   Reconstruction: f(v) = h(0, rank, SibLabel, gamma).  ← note order
			// At level > 0: f(v) = h(level, rank, f(rgt), f(dwn))
			//   gamma = f(rgt). SibLabel = f(dwn).
			//   Reconstruction: f(v) = h(level, rank, gamma, SibLabel).
			step.Right = true
			if node.level == 0 {
				// The tag of this level-0 node is the "left" argument in the hash.
				if node.isSentinel {
					step.SibLabel = nullLabel
				} else {
					step.SibLabel = node.tag
				}
			} else {
				// Internal node: sib = f(down)
				step.SibLabel = safeLabel(node.down)
				step.Q = rankOf(node.down)
			}
		} else {
			// We moved DOWN from node to reach the next path entry.
			// So gamma is now f(down subtree). Sib = f(right).
			// f(node) = h(level, rank, f(rgt), f(dwn))
			//          = h(level, rank, sib, gamma)
			step.Right = false
			step.SibLabel = safeLabel(node.right)
			step.Q = rankOf(node.right)
		}
		steps = append(steps, step)
	}

	return tagBytes, steps, nil
}

func safeLabel(v *slNode) []byte {
	if v == nil {
		return nullLabel
	}
	if v.label == nil {
		return nullLabel
	}
	return v.label
}

func rankOf(v *slNode) int {
	if v == nil {
		return 0
	}
	return v.rank
}

// ─── Verify (client) ─────────────────────────────────────────────────────────

// verifyPath reconstructs the root label from a BlockProof and compares it to basis.
//
// verifyPath implements Algorithm 2 (§3.3): reconstruct f(start) from the proof
// and verify it matches basis, then check the block's position.
//
// Reconstruction (Definition 3, §3.1):
//  1. step[0] (leaf, l=0):          gamma = h(0, Rank, Tag, SibLabel)
//  2. step[i], l=0, Right:          gamma = h(0, Rank, SibLabel, gamma)   [x(v), f(rgt)]
//  3. step[i], l>0, Right (d=rgt):  gamma = h(Level, Rank, SibLabel, gamma) [f(dwn), f(rgt)]
//  4. step[i], l>0, !Right (d=dwn): gamma = h(Level, Rank, gamma, SibLabel) [f(dwn), f(rgt)]
//
// Position check (Algorithm 2, §3.3): the sum of r(vⱼ) for all right-going
// steps equals pos (the 1-indexed block position). This prevents a server from
// substituting the path for a different block at a different position.
func verifyPath(basis Basis, pos int, bp BlockProof) (bool, error) {
	steps := bp.Steps
	if len(steps) == 0 {
		return false, fmt.Errorf("erway.verifyPath: empty proof steps")
	}

	step0 := steps[0]
	if step0.Level != 0 {
		return false, fmt.Errorf("erway.verifyPath: step[0] level=%d, want 0", step0.Level)
	}

	var lEnc, rEnc [8]byte
	// Step 0: f(leaf) = h(0, r(v), x(v), f(rgt(v)))  [Definition 3, Case 2]
	binary.BigEndian.PutUint64(lEnc[:], 0)
	binary.BigEndian.PutUint64(rEnc[:], uint64(step0.Rank))
	gamma := nodeHash(lEnc[:], rEnc[:], bp.Tag, step0.SibLabel)

	for i := 1; i < len(steps); i++ {
		step := steps[i]
		binary.BigEndian.PutUint64(lEnc[:], uint64(step.Level))
		binary.BigEndian.PutUint64(rEnc[:], uint64(step.Rank))

		if step.Level == 0 && step.Right {
			// Level-0 non-leaf, d=rgt: f(v) = h(0, r(v), x(v), f(rgt(v)))
			// gamma = f(rgt(v)). SibLabel = x(v) (block tag).
			gamma = nodeHash(lEnc[:], rEnc[:], step.SibLabel, gamma)
		} else if step.Right {
			// Internal, d=rgt: f(v) = h(l(v), r(v), f(dwn(v)), f(rgt(v)))  [Definition 3, Case 1]
			// gamma = f(rgt(v)). SibLabel = f(dwn(v)).
			gamma = nodeHash(lEnc[:], rEnc[:], step.SibLabel, gamma)
		} else {
			// Internal, d=dwn: f(v) = h(l(v), r(v), f(dwn(v)), f(rgt(v)))  [Definition 3, Case 1]
			// gamma = f(dwn(v)). SibLabel = f(rgt(v)).
			gamma = nodeHash(lEnc[:], rEnc[:], gamma, step.SibLabel)
		}
	}

	if !equal32(gamma, []byte(basis)) {
		return false, nil
	}

	// Position check (Algorithm 2, §3.3): sum of r(vⱼ) for right-going steps = pos.
	// Each right-going step contributes its rank — the count of data blocks
	// "passed" at that step (1 for a data leaf, r(v) for higher-level nodes).
	posCheck := step0.Rank // leaf: r(v)=1
	for i := 1; i < len(steps); i++ {
		if steps[i].Right {
			posCheck += steps[i].Rank
		}
	}
	return posCheck == pos, nil
}

// ─── Challenge, Prove, VerifyProof ───────────────────────────────────────────

// Challenge is the client's audit query (§4.1).
type Challenge struct {
	Indices []int      // 1-indexed block positions, len C
	Coeffs  []*big.Int // random coefficients aⱼ, len C
	N       int        // block count at challenge time
}

// MakeChallenge generates a fresh Challenge for c blocks out of n (§4.1).
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

// Proof is the server's response to a Challenge (§4.1, §4.2).
type Proof struct {
	Blocks []BlockProof
	M      *big.Int // Σ aⱼ · SHA-256(blockᵢⱼ) as integer
}

// Prove computes the DPDP I proof for the challenged blocks.
// store is 0-indexed; erway uses 1-indexed positions internally, so Block(idx-1) is called.
func Prove(s *suite.Suite, pk *pdp.PublicKey, sl *SkipList, chal *Challenge, store blocks.BlockStore) (*Proof, error) {
	if chal.N != sl.n {
		return nil, fmt.Errorf("erway.Prove: challenge N=%d but skip list n=%d", chal.N, sl.n)
	}

	bps := make([]BlockProof, len(chal.Indices))
	M := big.NewInt(0)

	for t, idx := range chal.Indices {
		tagBytes, steps, err := sl.atRank(idx)
		if err != nil {
			return nil, fmt.Errorf("erway.Prove: atRank(%d): %w", idx, err)
		}
		bps[t] = BlockProof{Tag: tagBytes, Steps: steps}

		block, err := store.Block(idx - 1) // erway uses 1-indexed positions; BlockStore is 0-indexed
		if err != nil {
			return nil, fmt.Errorf("erway.Prove: block %d: %w", idx, err)
		}
		M.Add(M, new(big.Int).Mul(chal.Coeffs[t], s.HashBlock(block)))
	}

	return &Proof{Blocks: bps, M: M}, nil
}

// VerifyProof verifies the server's proof against the client's basis (§4.1, §4.2).
func VerifyProof(pk *pdp.PublicKey, basis Basis, chal *Challenge, proof *Proof) (bool, error) {
	if len(proof.Blocks) != len(chal.Indices) {
		return false, fmt.Errorf("erway.VerifyProof: proof has %d block proofs, want %d",
			len(proof.Blocks), len(chal.Indices))
	}

	// Step 1: verify each skip-list path against the basis.
	for t, idx := range chal.Indices {
		ok, err := verifyPath(basis, idx, proof.Blocks[t])
		if err != nil {
			return false, fmt.Errorf("erway.VerifyProof: path[%d] (block %d): %w", t, idx, err)
		}
		if !ok {
			return false, nil
		}
	}

	// Step 2: check g^M = ∏ T(blockᵢⱼ)^{aⱼ} mod N (§4.2).
	rhs := big.NewInt(1)
	for t := range chal.Indices {
		tag := new(big.Int).SetBytes(proof.Blocks[t].Tag)
		term := new(big.Int).Exp(tag, chal.Coeffs[t], pk.N)
		rhs.Mul(rhs, term)
		rhs.Mod(rhs, pk.N)
	}
	lhs := new(big.Int).Exp(pk.G, proof.M, pk.N)

	return lhs.Cmp(rhs) == 0, nil
}

// ─── Updates (§3.4) ───────────────────────────────────────────────────────────

// UpdateKind distinguishes the three supported update types.
type UpdateKind int

const (
	Modify UpdateKind = iota
	Insert
	Delete
)

// UpdateOp describes one dynamic update.
type UpdateOp struct {
	Kind  UpdateKind
	Index int    // 1-indexed block position
	Data  []byte // new block bytes (nil for Delete)
}

// UpdateResult is returned by PerformUpdate.
type UpdateResult struct {
	OldTag   []byte      // T(old block) before the update
	OldSteps []ProofStep // pre-update verification path
	NewBasis []byte      // the actual new basis (authoritative after client verification)
}

// PerformUpdate applies an update on the server side.
func PerformUpdate(s *suite.Suite, pk *pdp.PublicKey, sl *SkipList, op UpdateOp) (*UpdateResult, error) {
	var oldTag []byte
	var oldSteps []ProofStep
	var err error

	switch op.Kind {
	case Modify:
		if op.Index < 1 || op.Index > sl.n {
			return nil, fmt.Errorf("erway.PerformUpdate: Modify index %d out of range [1,%d]", op.Index, sl.n)
		}
		oldTag, oldSteps, err = sl.atRank(op.Index)
		if err != nil {
			return nil, err
		}
		if err := sl.modifyAt(s, pk, op.Index, op.Data); err != nil {
			return nil, err
		}

	case Insert:
		if op.Index < 0 || op.Index > sl.n {
			return nil, fmt.Errorf("erway.PerformUpdate: Insert index %d out of range [0,%d]", op.Index, sl.n)
		}
		if op.Index > 0 {
			oldTag, oldSteps, err = sl.atRank(op.Index)
			if err != nil {
				return nil, err
			}
		}
		if err := sl.doInsert(s, pk, op.Index+1, op.Data, coinHeight(sl.maxHeight())); err != nil {
			return nil, err
		}

	case Delete:
		if op.Index < 1 || op.Index > sl.n {
			return nil, fmt.Errorf("erway.PerformUpdate: Delete index %d out of range [1,%d]", op.Index, sl.n)
		}
		// §3.4 Algorithm 3: proof is atRank(i-1) so the client holds a witness
		// that survives the deletion. For block 1 there is no predecessor.
		if op.Index > 1 {
			oldTag, oldSteps, err = sl.atRank(op.Index - 1)
			if err != nil {
				return nil, err
			}
		}
		if err := sl.deleteAt(op.Index); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("erway.PerformUpdate: unknown op kind %d", op.Kind)
	}

	newBasis := make([]byte, 32)
	copy(newBasis, sl.rootLabel())

	return &UpdateResult{
		OldTag:   oldTag,
		OldSteps: oldSteps,
		NewBasis: newBasis,
	}, nil
}

// modifyAt replaces the tag of the block at 1-indexed position pos.
func (sl *SkipList) modifyAt(s *suite.Suite, pk *pdp.PublicKey, pos int, block []byte) error {
	// Find the bottom-level node at pos.
	v := sl.levels[0]
	count := 0
	for v != nil {
		if !v.isSentinel {
			count++
			if count == pos {
				v.tag = BlockTag(s, pk, block).Bytes()
				sl.recomputeLabels()
				return nil
			}
		}
		v = v.right
	}
	return fmt.Errorf("erway.modifyAt: pos=%d not found (n=%d)", pos, sl.n)
}

// deleteAt removes the block at 1-indexed position pos.
func (sl *SkipList) deleteAt(pos int) error {
	if pos < 1 || pos > sl.n {
		return fmt.Errorf("erway.deleteAt: pos=%d out of range", pos)
	}

	// Find the target node at the bottom level.
	var target *slNode
	{
		v := sl.levels[0]
		count := 0
		for v != nil {
			if !v.isSentinel {
				count++
				if count == pos {
					target = v
					break
				}
			}
			v = v.right
		}
	}
	if target == nil {
		return fmt.Errorf("erway.deleteAt: pos=%d not found", pos)
	}

	// Remove all nodes in the target's tower at each level.
	// For each level, find the predecessor of the target's tower node and splice it out.
	for lvl := 0; lvl < len(sl.levels); lvl++ {
		// Find the node at level lvl that is in the tower of target.
		// The tower of target at level lvl can be found by starting at sl.levels[lvl]
		// and walking until we find the node whose down chain reaches target.

		// Build the set of tower nodes: start from target and walk up via right.
		// Actually, we don't have up pointers. Instead, we find tower nodes by
		// walking the level list and checking if any node's down path leads to target.

		// For each level, walk until we find the predecessor of target's tower node.
		v := sl.levels[lvl]
		for v.right != nil {
			if isInTowerOf(v.right, target) {
				// Splice out v.right.
				v.right = v.right.right
				break
			}
			v = v.right
		}
	}

	sl.n--
	sl.recomputeRanks()
	sl.recomputeLabels()
	return nil
}

// isInTowerOf returns true if node w is in the same tower as target
// (i.e., w's down chain eventually reaches target).
func isInTowerOf(w, target *slNode) bool {
	if w.level == 0 {
		return w == target
	}
	// Walk down the chain.
	curr := w
	for curr != nil {
		if curr == target {
			return true
		}
		curr = curr.down
	}
	return false
}

// VerifyUpdate implements Algorithm 4 (§3.4): verify the pre-update path and
// return the new basis supplied by the server.
func VerifyUpdate(pk *pdp.PublicKey, basis Basis, op UpdateOp, result *UpdateResult) (Basis, bool, error) {
	if result.OldTag != nil && len(result.OldSteps) > 0 {
		// Determine which position the pre-update proof covers.
		// §3.4 Algorithm 3/4: for deletion, proof is atRank(i-1).
		refPos := op.Index
		switch op.Kind {
		case Insert:
			if refPos == 0 {
				goto skipVerify // insertion at head has no predecessor proof
			}
		case Delete:
			refPos = op.Index - 1 // predecessor block (still exists post-deletion)
			if refPos == 0 {
				goto skipVerify // deletion of block 1 has no predecessor
			}
		}
		ok, err := verifyPath(basis, refPos, BlockProof{Tag: result.OldTag, Steps: result.OldSteps})
		if err != nil {
			return nil, false, fmt.Errorf("erway.VerifyUpdate: verifyPath: %w", err)
		}
		if !ok {
			return nil, false, nil
		}
	}

skipVerify:
	newBasis := make(Basis, 32)
	copy(newBasis, result.NewBasis)
	return newBasis, true, nil
}
