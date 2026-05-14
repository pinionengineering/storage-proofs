// Package dagpdp adapts the S-PDP protocol from the pdp/ateniese package to IPFS DAGs.
//
// A client walks an IPFS content DAG, computes an S-PDP tag for each block,
// and assembles the result into a TagList — an ordered set of (CID, Tag) pairs
// with an explicit ContentRoot field identifying the DAG root to be pinned.
//
// An IPFS plugin on the storage node is given the TagList. It reads
// TagList.ContentRoot and pins it so the original content is announced on the
// DHT normally. The tags are stored alongside the pin and are not announced
// separately.
//
// Challenge / proof flow:
//
//  1. Verifier generates an ateniese.Challenge (using K1/PRP for block selection).
//  2. Storage node calls GenProof, which fetches only the challenged blocks
//     from its pin store by CID and delegates to ateniese.GenProof.
//  3. Verifier calls CheckProof.
package dagpdp

import (
	"fmt"
	"math/big"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/pdp/ateniese"
	"github.com/pinionengineering/storage-proofs/suite"
)

// TagBlock pairs an IPFS block's content address with its S-PDP tag.
type TagBlock struct {
	CID cid.Cid
	Tag *ateniese.Tag
}

// TagList is an ordered set of TagBlocks covering all blocks in a content DAG.
//
// ContentRoot is the root CID of the original content DAG. An IPFS plugin
// reads this field and pins it so the content is announced on the DHT; nothing
// else in TagList implies which CID is the root.
//
// Blocks is the complete ordered list of tagged blocks in the DAG walk order
// the prover and verifier agree on. Challenge indices are positions into this
// slice: Blocks[i].CID identifies the block to fetch, Blocks[i].Tag is used
// for proof generation.
type TagList struct {
	ContentRoot cid.Cid
	Blocks      []TagBlock
}

// BuildTagList computes S-PDP tags for all blocks in a DAG walk.
//
// contentRoot is the root CID of the original content DAG, stored explicitly
// so the IPFS plugin knows what to pin without relying on block ordering.
//
// blks is the complete ordered list of DAG blocks to tag. The walk order is
// caller-determined; whichever order is used must be reproduced consistently
// by both the prover and the verifier when resolving challenge indices.
func BuildTagList(s *suite.Suite, pk *pdp.PublicKey, sk *ateniese.SecretKey, contentRoot cid.Cid, blks []blocks.Block) (*TagList, error) {
	if len(blks) == 0 {
		return nil, fmt.Errorf("dagpdp: blks must not be empty")
	}

	tagBlocks := make([]TagBlock, len(blks))
	for i, b := range blks {
		cidBytes := b.Cid().Bytes()
		w := make([]byte, 0, len(sk.V)+len(cidBytes))
		w = append(w, sk.V...)
		w = append(w, cidBytes...)

		tag, err := ateniese.TagBlock(s, pk, sk, b.RawData(), w)
		if err != nil {
			return nil, fmt.Errorf("dagpdp: tag for block %d: %w", i, err)
		}
		tagBlocks[i] = TagBlock{CID: b.Cid(), Tag: tag}
	}

	return &TagList{ContentRoot: contentRoot, Blocks: tagBlocks}, nil
}

// Tags returns the ateniese.Tag slice in Blocks order, suitable for passing
// directly to ateniese.GenProof and ateniese.CheckProof.
func (tl *TagList) Tags() []*ateniese.Tag {
	tags := make([]*ateniese.Tag, len(tl.Blocks))
	for i, tb := range tl.Blocks {
		tags[i] = tb.Tag
	}
	return tags
}

// GenProof generates a proof of possession for the blocks selected by chal.
//
// fetch is called once per challenged block to retrieve its raw bytes from the
// node's pin store by CID. Only the C selected blocks are fetched.
//
// chal must have been constructed for this TagList (same SuiteID,
// C ≤ len(tl.Blocks)).
func GenProof(tl *TagList, pk *pdp.PublicKey, chal *ateniese.Challenge, fetch func(cid.Cid) ([]byte, error)) (*ateniese.Proof, error) {
	s, ok := suite.SuiteByID(chal.SuiteID)
	if !ok {
		return nil, fmt.Errorf("dagpdp: unknown suite ID %d", chal.SuiteID)
	}

	n := len(tl.Blocks)
	perm := s.BuildPRP(chal.K1, n)

	// Build parallel slices for ateniese.GenProof, fetching data only for the C
	// challenged positions. Non-challenged positions are nil and never accessed.
	blockData := make([][]byte, n)
	tags := make([]*ateniese.Tag, n)
	for j := 1; j <= chal.C; j++ {
		ij := perm[j-1]
		tags[ij] = tl.Blocks[ij].Tag

		data, err := fetch(tl.Blocks[ij].CID)
		if err != nil {
			return nil, fmt.Errorf("dagpdp: fetch block %d (%s): %w", ij, tl.Blocks[ij].CID, err)
		}
		blockData[ij] = data
	}

	return ateniese.GenProof(s, pk, blockData, chal, tags)
}

// CheckProof verifies a proof returned by GenProof.
func CheckProof(tl *TagList, pk *pdp.PublicKey, sk *ateniese.SecretKey, secret *big.Int, chal *ateniese.Challenge, proof *ateniese.Proof) (bool, error) {
	s, ok := suite.SuiteByID(chal.SuiteID)
	if !ok {
		return false, fmt.Errorf("dagpdp: unknown suite ID %d", chal.SuiteID)
	}
	return ateniese.CheckProof(s, pk, sk, secret, tl.Tags(), chal, proof)
}
