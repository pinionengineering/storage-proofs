// Package dagpor adapts the POR protocol from the por package to IPFS DAGs.
//
// A client walks an IPFS content DAG, encodes it with POR (applying SA-ECC
// and precomputing sentinels), and assembles the result into an EncodedDAG —
// an ordered set of CIDs for all encoded blocks (original + parity) plus
// the sentinel metadata.
//
// An IPFS plugin on the storage node is given the EncodedDAG. It reads
// EncodedDAG.ContentRoot and pins it so the original content is announced on
// the DHT. Parity blocks are stored as independent IPFS blocks (uploaded by
// the client via BuildEncodedDAG's second return value). Sentinels and the
// file MAC are stored as metadata alongside the pin.
//
// Challenge / response flow:
//
//  1. Client calls bjo.MakeChallenge to generate a challenge.
//  2. Storage node calls Respond, which fetches only the V challenged blocks
//     from its block store by CID and computes the inner code response.
//  3. Client calls Verify (delegates to bjo.Verify).
package dagpor

import (
	"fmt"
	"math/big"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/pinionengineering/storage-proofs/pdp"
	"github.com/pinionengineering/storage-proofs/por/bjo"
)

// EncodedBlock pairs a position in the encoded file with its IPFS CID.
// For original file blocks (index < NumMessage) the CID is the content-
// addressed CID of the block in the pinned DAG. For parity blocks the CID
// is derived from the encrypted parity data via blocks.NewBlock.
type EncodedBlock struct {
	CID cid.Cid
}

// EncodedDAG is the POR encoding of an IPFS content DAG.
//
// ContentRoot is the root CID of the original content DAG. An IPFS plugin
// reads this field and pins it so the content is announced on the DHT.
//
// Blocks is the complete ordered list of encoded blocks in the same order
// that bjo.Encode assigns them: Blocks[0:NumMessage] are the original content
// blocks (systematic property of SA-ECC), and Blocks[NumMessage:] are the
// encrypted parity blocks. Challenge indices are positions into this slice:
// Blocks[i].CID identifies the block to fetch during Respond.
type EncodedDAG struct {
	ContentRoot cid.Cid
	Blocks      []EncodedBlock
	NumMessage  int
	Sentinels   [][]byte
	FileMAC     []byte
	Params      *bjo.Params
}

// BuildEncodedDAG encodes a content DAG for POR storage.
//
// contentRoot is the root CID of the original content DAG, stored explicitly
// so the IPFS plugin knows what to pin without relying on block ordering.
//
// blks is the complete ordered list of DAG blocks to encode. The walk order
// is caller-determined; it must be reproduced consistently by both the prover
// and the verifier when resolving challenge indices.
//
// The second return value is the set of parity blocks computed by SA-ECC,
// each as an IPFS block whose CID matches the corresponding entry in
// EncodedDAG.Blocks[NumMessage:]. The caller is responsible for storing
// these blocks in the server's block store so Respond can fetch them by CID.
func BuildEncodedDAG(mk *bjo.MasterKey, contentRoot cid.Cid, blks []blocks.Block) (*EncodedDAG, []blocks.Block, error) {
	if len(blks) == 0 {
		return nil, nil, fmt.Errorf("dagpor: blks must not be empty")
	}

	fileBlocks := make([][]byte, len(blks))
	for i, b := range blks {
		fileBlocks[i] = b.RawData()
	}

	ef, err := bjo.Encode(mk, fileBlocks)
	if err != nil {
		return nil, nil, fmt.Errorf("dagpor: %w", err)
	}

	encodedBlocks := make([]EncodedBlock, len(ef.Blocks))
	// Original blocks: preserve their content-addressed CIDs.
	for i, b := range blks {
		encodedBlocks[i] = EncodedBlock{CID: b.Cid()}
	}
	// Parity blocks: compute CIDs from the encrypted parity data.
	parityBlocks := make([]blocks.Block, len(ef.Blocks)-len(blks))
	for i := len(blks); i < len(ef.Blocks); i++ {
		pb := blocks.NewBlock(ef.Blocks[i])
		encodedBlocks[i] = EncodedBlock{CID: pb.Cid()}
		parityBlocks[i-len(blks)] = pb
	}

	ed := &EncodedDAG{
		ContentRoot: contentRoot,
		Blocks:      encodedBlocks,
		NumMessage:  ef.NumMessage,
		Sentinels:   ef.Sentinels,
		FileMAC:     ef.FileMAC,
		Params:      ef.Params,
	}
	return ed, parityBlocks, nil
}

// Respond computes a POR response for chal, fetching only the V challenged blocks.
//
// fetch is called once per challenged block to retrieve its raw bytes from the
// node's block store by CID. Only the V selected blocks are fetched.
//
// The inner code response is computed identically to bjo.Respond:
//
//	M = Σ_{s=1}^v F̃_{i_s} · G[s][u]  mod P
//
// where F̃_{i_s} = SetBytes(block_{i_s}) mod P and G[s][u] = PRF(GSeed, u, s)
// mod P. Block indices are derived from chal.Kjc via pdp.SuiteV1.BuildPRP,
// matching the derivation in bjo.Respond exactly. The challenged sentinel Q_j
// is retrieved from ed.Sentinels[chal.J-1].
func Respond(ed *EncodedDAG, chal *bjo.Challenge, fetch func(cid.Cid) ([]byte, error)) (*bjo.Response, error) {
	p := ed.Params
	t := len(ed.Blocks)

	if chal.J < 1 || chal.J > p.Q {
		return nil, fmt.Errorf("dagpor: j=%d out of range [1, %d]", chal.J, p.Q)
	}
	if chal.U < 1 || chal.U > p.W {
		return nil, fmt.Errorf("dagpor: u=%d out of range [1, %d]", chal.U, p.W)
	}

	// Derive v block indices using the same PRP as bjo.blockIndices.
	indices := pdp.SuiteV1.BuildPRP(chal.Kjc, t)[:p.V]

	// Compute M = Σ_{s=1}^v F̃_{i_s}·G[s][u] mod P, fetching each block by CID.
	P := p.P
	M := big.NewInt(0)
	for s, idx := range indices {
		data, err := fetch(ed.Blocks[idx].CID)
		if err != nil {
			return nil, fmt.Errorf("dagpor: fetch block %d (%s): %w", idx, ed.Blocks[idx].CID, err)
		}
		Fi := new(big.Int).Mod(new(big.Int).SetBytes(data), P)
		// G[s+1][u] = PRF(GSeed, u, s+1) mod P; matches bjo.innerCodeElement convention.
		Gsu := new(big.Int).Mod(pdp.SuiteV1.PRF(p.GSeed, chal.U, s+1), P)
		M.Add(M, new(big.Int).Mul(Fi, Gsu))
		M.Mod(M, P)
	}

	// Encode M as fixed-length big-endian bytes of length (P.BitLen()+7)/8.
	pLen := (P.BitLen() + 7) / 8
	mBytes := M.Bytes()
	mFixed := make([]byte, pLen)
	copy(mFixed[pLen-len(mBytes):], mBytes)

	return &bjo.Response{
		Mj: mFixed,
		Qj: ed.Sentinels[chal.J-1],
	}, nil
}

// Verify checks whether the server's response to chal is correct.
// Delegates to bjo.Verify.
func Verify(mk *bjo.MasterKey, chal *bjo.Challenge, resp *bjo.Response) (bool, error) {
	return bjo.Verify(mk, chal, resp)
}
