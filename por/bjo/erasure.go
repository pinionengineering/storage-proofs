// Standalone erasure-coding helpers for callers who want to supply their own
// outer redundancy instead of por/bjo's own SA-ECC (§4.2).
//
// §4.2.1's own encode algorithm bakes outer erasure coding in as step 2: what
// gets stored on the server is never the raw file, it's the SA-ECC-encoded
// form, and Phase II of Extract depends on that redundancy to reconstruct
// blocks the server has genuinely lost. A caller who wants to bring their
// own erasure code instead of por/bjo's SA-ECC (a different code, a
// different redundancy ratio, or managing it entirely outside this package)
// still needs *some* source of redundancy present in what's stored -- there
// is no way around that if full recovery from missing blocks is a goal.
//
// This file offers exactly that as ready-made, optional building blocks, so
// a caller isn't required to reach into por/bjo's own SA-ECC internals
// (which additionally hide stripe boundaries from an adversarial server, a
// property this simpler code does not provide) to get something working:
//
//	encodedStore, _ := bjo.ErasureEncodeStore(rawStore, outerK, outerN)
//	mk, _ := bjo.KeyGen(&bjo.Params{..., OuterN: encodedStore.Len(), OuterK: encodedStore.Len()})
//	ef, _ := bjo.Encode(suite.SuiteV1, mk, encodedStore) // pass-through outer layer
//	// upload ef; later, some blocks may be lost at the server
//	recoveredStore, _ := bjo.ExtractPhaseIStore(suite.SuiteV1, mk, ef)
//	// numMessage here is rawStore.Len() (the count *before* ErasureEncodeStore),
//	// not ef.NumMessage -- see ErasureDecodeStore's doc comment.
//	fileStore, _ := bjo.ErasureDecodeStore(recoveredStore, rawStore.Len(), outerK, outerN)
//	// VerifyFileMAC needs the file shaped exactly like whatever was fed to
//	// Encode -- here that's the full encodedStore-shaped representation, not
//	// fileStore's raw message blocks, so re-derive it before checking (RS
//	// encoding is deterministic and keyless in this simpler layer, so this
//	// reproduces encodedStore's original content exactly).
//	reEncoded, _ := bjo.ErasureEncodeStore(fileStore, outerK, outerN)
//	ok, _ := bjo.VerifyFileMAC(suite.SuiteV1, mk, ef, fileBlocksFrom(reEncoded))
//
// Setting Params.OuterN = Params.OuterK makes por/bjo's own SA-ECC a
// pass-through (zero parity blocks of its own -- see saeccEncode/
// saeccDecode), which is what makes it safe to layer external redundancy
// underneath it this way without double-encoding.
package bjo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

// ErasureEncodeStore applies a plain systematic Reed-Solomon code to store's
// blocks and returns a new store holding the original blocks followed by
// the RS parity blocks, stripe by stripe -- the same systematic layout
// saeccEncode produces (original file unchanged, all parity appended after
// it), but with no permutation or encryption of the parity blocks. Unlike
// saeccEncode, this does not hide stripe boundaries from an adversarial
// server (§4.2's "adversarial code" property); a caller who wants that
// property should use por/bjo's own Encode/OuterN>OuterK path instead of
// this helper.
//
// Blocks are grouped into stripes of outerK; each stripe is independently
// RS-encoded into outerN blocks (outerN-outerK parity blocks per stripe). A
// short final stripe is zero-padded, mirroring saeccEncode.
func ErasureEncodeStore(store blocks.BlockStore, outerK, outerN int) (blocks.BlockStore, error) {
	if outerK <= 0 || outerN < outerK {
		return nil, fmt.Errorf("por: ErasureEncodeStore: need 0 < outerK <= outerN, got outerK=%d outerN=%d", outerK, outerN)
	}
	m := store.Len()
	if m == 0 {
		return nil, fmt.Errorf("por: ErasureEncodeStore: empty store")
	}

	file := make([][]byte, m)
	for i := range m {
		b, err := blocks.BlockAt(store, i)
		if err != nil {
			return nil, fmt.Errorf("por: ErasureEncodeStore: block %d: %w", i, err)
		}
		file[i] = b
	}
	blockSize := len(file[0])

	numStripes := (m + outerK - 1) / outerK
	numParityPerStripe := outerN - outerK
	totalParity := numStripes * numParityPerStripe

	allParity := make([][]byte, 0, totalParity)
	for stripe := range numStripes {
		start := stripe * outerK
		end := start + outerK
		if end > m {
			end = m
		}
		stripeBlocks := make([][]byte, outerK)
		copy(stripeBlocks, file[start:end])
		for j := end - start; j < outerK; j++ {
			stripeBlocks[j] = make([]byte, blockSize) // zero-pad short last stripe
		}
		encoded := rsEncodeBlocks(stripeBlocks, outerN)
		allParity = append(allParity, encoded[outerK:]...)
	}

	out := make([][]byte, m+totalParity)
	copy(out[:m], file)
	copy(out[m:], allParity)
	return blocks.NewMemStore(out), nil
}

// ErasureDecodeStore reverses ErasureEncodeStore: reconstructs the original
// numMessage blocks from a store in ErasureEncodeStore's layout, tolerating
// up to outerN-outerK missing blocks (Block returning nil with no error;
// the same erasure convention saeccDecode's own doc comment establishes)
// per stripe, in any mix of message and parity positions.
//
// numMessage is the block count *before* ErasureEncodeStore was applied
// (e.g. len(original) for the raw file) -- not ef.NumMessage from the
// EncodedFile Encode produced. Those are different things: ef.NumMessage is
// por/bjo's own count over whatever store was handed to Encode, which in
// the pass-through setup this file's package doc describes is already
// ErasureEncodeStore's larger, redundancy-included output.
func ErasureDecodeStore(store blocks.BlockStore, numMessage, outerK, outerN int) (blocks.BlockStore, error) {
	if outerK <= 0 || outerN < outerK {
		return nil, fmt.Errorf("por: ErasureDecodeStore: need 0 < outerK <= outerN, got outerK=%d outerN=%d", outerK, outerN)
	}
	numStripes := (numMessage + outerK - 1) / outerK
	numParityPerStripe := outerN - outerK
	totalParity := numStripes * numParityPerStripe
	t := numMessage + totalParity
	if store.Len() != t {
		return nil, fmt.Errorf("por: ErasureDecodeStore: store has %d blocks, want %d", store.Len(), t)
	}

	fetch := func(i int) ([]byte, error) { return blocks.BlockAt(store, i) }

	var blockSize int
	for i := range t {
		b, err := fetch(i)
		if err != nil {
			return nil, fmt.Errorf("por: ErasureDecodeStore: block %d: %w", i, err)
		}
		if b != nil {
			blockSize = len(b)
			break
		}
	}
	if blockSize == 0 {
		return nil, fmt.Errorf("por: ErasureDecodeStore: all blocks are missing")
	}

	result := make([][]byte, numMessage)
	for stripe := range numStripes {
		start := stripe * outerK
		end := start + outerK
		if end > numMessage {
			end = numMessage
		}

		stripeBlocks := make([][]byte, outerN)
		for j := start; j < end; j++ {
			b, err := fetch(j)
			if err != nil {
				return nil, fmt.Errorf("por: ErasureDecodeStore: block %d: %w", j, err)
			}
			stripeBlocks[j-start] = b
		}
		for j := end - start; j < outerK; j++ {
			stripeBlocks[j] = make([]byte, blockSize) // short last stripe, mirrors ErasureEncodeStore's zero-pad
		}
		for j := range numParityPerStripe {
			b, err := fetch(numMessage + stripe*numParityPerStripe + j)
			if err != nil {
				return nil, fmt.Errorf("por: ErasureDecodeStore: parity block %d: %w", stripe*numParityPerStripe+j, err)
			}
			stripeBlocks[outerK+j] = b
		}

		decoded, err := rsDecodeBlocks(stripeBlocks, outerK)
		if err != nil {
			return nil, fmt.Errorf("por: ErasureDecodeStore: stripe %d: %w", stripe, err)
		}
		copy(result[start:end], decoded[:end-start])
	}
	return blocks.NewMemStore(result), nil
}

// ExtractPhaseIStore runs Phase I extraction (§4.2.1 extract step 1) over ef
// and returns the result as a BlockStore: recovered blocks at their
// original positions, nil wherever Phase I couldn't reach majority
// agreement (an erasure).
//
// This is the counterpart to ErasureEncodeStore/ErasureDecodeStore for a
// caller supplying their own outer erasure code. Extract's own Phase II
// always calls this package's saeccDecode internally and hard-fails if that
// can't fully reconstruct the file -- which makes Extract unusable when
// Params.OuterN=Params.OuterK, a pass-through outer layer with no
// redundancy of its own to decode from. ExtractPhaseIStore gives direct
// access to Phase I's own output instead, for a caller to apply
// ErasureDecodeStore (or any decoder of their own) to afterward.
//
// Requires Params.Alpha > 0.
func ExtractPhaseIStore(s *suite.Suite, mk *MasterKey, ef *EncodedFile) (blocks.BlockStore, error) {
	if mk.Params.Alpha <= 0 {
		return nil, fmt.Errorf("por: ExtractPhaseIStore: requires Params.Alpha > 0")
	}
	recovered := extractPhaseI(s, mk, ef)
	return blocks.NewMemStore(recovered), nil
}

// VerifyFileMAC checks whether file, re-encoded exactly as Encode encoded
// the original (§4.2.1 encode step 4's MAC_kfileMAC(F̃)), reproduces the MAC
// stored in ef.FileMAC -- the same check Extract performs as its own final
// step. Exposed separately for a caller reconstructing file outside of
// Extract's own Phase I+Phase II pipeline, e.g. via ExtractPhaseIStore
// followed by ErasureDecodeStore.
//
// file must be shaped exactly like whatever was originally passed to
// Encode. In the ErasureEncodeStore/ExtractPhaseIStore/ErasureDecodeStore
// pattern this file's package doc describes, that's the full
// ErasureEncodeStore-shaped representation (message plus external RS
// parity), not ErasureDecodeStore's own output (which returns only the
// original message blocks, matching saeccDecode's established contract) --
// re-derive it with ErasureEncodeStore first if that's what you have.
func VerifyFileMAC(s *suite.Suite, mk *MasterKey, ef *EncodedFile, file [][]byte) (bool, error) {
	p := mk.Params
	reEncoded, err := saeccEncode(s, file, p.OuterN, p.OuterK, mk.KPerm, mk.KECCPerm, mk.KECCEnc)
	if err != nil {
		return false, fmt.Errorf("por: VerifyFileMAC: %w", err)
	}
	mac := hmac.New(sha256.New, mk.KMACFile)
	for _, b := range reEncoded {
		mac.Write(b)
	}
	for _, sentinel := range ef.Sentinels {
		mac.Write(sentinel)
	}
	return bytes.Equal(mac.Sum(nil), ef.FileMAC), nil
}
