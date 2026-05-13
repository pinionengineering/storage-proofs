package bjo

// Tests for the extraction (Phase II) portion of the POR protocol.
// §4.2.1 extract step 2: decode F from the SA-ECC encoded blocks using the
// outer RS code, then verify the file MAC.
//
// Phase I tests (RespondExtract, solveInnerCode, extractPhaseI) use 3-byte
// blocks so that SetBytes(block) < P = 2^31-1, satisfying the P > max(block
// value) requirement without a 256-bit prime.

import (
	"bytes"
	"math/big"
	"testing"
)

// defaultParams returns a small but complete parameter set for extraction tests.
// OuterN=6, OuterK=4 → 2 parity blocks per stripe, can correct up to 2 erasures.
func defaultParams() *Params {
	return &Params{
		V:      3,
		W:      10,
		Q:      5,
		P:      big.NewInt(2147483647),
		OuterN: 6,
		OuterK: 4,
	}
}

// encodeFile is a helper: KeyGen + Encode.
func encodeFile(t *testing.T, params *Params, numBlocks int) (*MasterKey, *EncodedFile, [][]byte) {
	t.Helper()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	blocks := randomBlocks(t, numBlocks, 32)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return mk, ef, blocks
}

// blockEqual reports whether two [][]byte slices are byte-for-byte identical.
func blockEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// rsDecodeBlocks unit tests
// ---------------------------------------------------------------------------

// TestRSDecodeBlocksRoundTrip verifies rsDecodeBlocks(rsEncodeBlocks(msg, n), k) == msg
// for several (k, n) pairs with no erasures.
func TestRSDecodeBlocksRoundTrip(t *testing.T) {
	for _, tc := range []struct{ k, n int }{{3, 5}, {4, 6}, {4, 7}, {6, 10}} {
		blocks := randomBlocks(t, tc.k, 32)
		encoded := rsEncodeBlocks(blocks, tc.n)
		recovered, err := rsDecodeBlocks(encoded, tc.k)
		if err != nil {
			t.Fatalf("(k=%d,n=%d) rsDecodeBlocks: %v", tc.k, tc.n, err)
		}
		for i := range tc.k {
			if !bytes.Equal(recovered[i], blocks[i]) {
				t.Fatalf("(k=%d,n=%d): block %d mismatch after decode", tc.k, tc.n, i)
			}
		}
	}
}

// TestRSDecodeBlocksWithErasures verifies that rsDecodeBlocks recovers the
// message when some message and/or parity positions are set to nil.
func TestRSDecodeBlocksWithErasures(t *testing.T) {
	k, n := 4, 7 // 3 parity symbols → can correct up to 3 erasures
	blocks := randomBlocks(t, k, 32)
	encoded := rsEncodeBlocks(blocks, n)

	// Erase one message block and one parity block.
	codeword := make([][]byte, n)
	copy(codeword, encoded)
	codeword[1] = nil   // erase message block 1
	codeword[k+1] = nil // erase parity block 1

	recovered, err := rsDecodeBlocks(codeword, k)
	if err != nil {
		t.Fatalf("rsDecodeBlocks with 2 erasures: %v", err)
	}
	for i := range k {
		if !bytes.Equal(recovered[i], blocks[i]) {
			t.Fatalf("block %d mismatch after erasure recovery", i)
		}
	}
}

// TestRSDecodeBlocksTooManyErasures verifies that rsDecodeBlocks returns an
// error when fewer than k blocks are non-nil.
func TestRSDecodeBlocksTooManyErasures(t *testing.T) {
	k, n := 4, 6
	encoded := rsEncodeBlocks(randomBlocks(t, k, 32), n)

	// Erase all but k-1 blocks.
	codeword := make([][]byte, n)
	for i := range k - 1 {
		codeword[i] = encoded[i]
	}
	// Rest are nil.
	_, err := rsDecodeBlocks(codeword, k)
	if err == nil {
		t.Fatal("expected error for too many erasures, got nil")
	}
}

// TestRSDecodeBlocksOnlyParityPresent verifies recovery when all message blocks
// are erased but enough parity blocks remain.
// k=3, n=6: 3 parity blocks; erasing all 3 message blocks leaves exactly k=3
// parity blocks, which is the minimum required.
func TestRSDecodeBlocksOnlyParityPresent(t *testing.T) {
	k, n := 3, 6
	blocks := randomBlocks(t, k, 32)
	encoded := rsEncodeBlocks(blocks, n)

	// Erase all message blocks; keep all parity blocks.
	codeword := make([][]byte, n)
	for i := k; i < n; i++ {
		codeword[i] = encoded[i]
	}

	recovered, err := rsDecodeBlocks(codeword, k)
	if err != nil {
		t.Fatalf("rsDecodeBlocks with all message blocks erased: %v", err)
	}
	for i := range k {
		if !bytes.Equal(recovered[i], blocks[i]) {
			t.Fatalf("block %d mismatch when recovering from parity only", i)
		}
	}
}

// ---------------------------------------------------------------------------
// SA-ECC round-trip tests
// ---------------------------------------------------------------------------

// TestSAECCRoundTrip verifies saeccDecode(saeccEncode(blocks)) == blocks for
// several file sizes including non-multiples of OuterK (short last stripe).
func TestSAECCRoundTrip(t *testing.T) {
	kPerm := randomBlock(t, 32)
	kECCPerm := randomBlock(t, 32)
	kECCEnc := randomBlock(t, 32)
	outerN, outerK := 6, 4

	for _, m := range []int{4, 8, 9, 12, 20} {
		blocks := randomBlocks(t, m, 32)
		encoded, err := saeccEncode(blocks, outerN, outerK, kPerm, kECCPerm, kECCEnc)
		if err != nil {
			t.Fatalf("m=%d saeccEncode: %v", m, err)
		}
		decoded, err := saeccDecode(encoded, m, outerN, outerK, kPerm, kECCPerm, kECCEnc)
		if err != nil {
			t.Fatalf("m=%d saeccDecode: %v", m, err)
		}
		if !blockEqual(decoded, blocks) {
			t.Fatalf("m=%d: decoded != original", m)
		}
	}
}

// TestSAECCDecodeWithParityErasures verifies saeccDecode recovers the original
// file when one parity block per stripe is set to nil. With outerN=6, outerK=4
// (2 parity per stripe), a single parity erasure per stripe is correctable.
func TestSAECCDecodeWithParityErasures(t *testing.T) {
	kPerm := randomBlock(t, 32)
	kECCPerm := randomBlock(t, 32)
	kECCEnc := randomBlock(t, 32)
	outerN, outerK := 6, 4
	m := 8 // 2 stripes

	blocks := randomBlocks(t, m, 32)
	encoded, err := saeccEncode(blocks, outerN, outerK, kPerm, kECCPerm, kECCEnc)
	if err != nil {
		t.Fatalf("saeccEncode: %v", err)
	}

	// Erase the first parity block (position m).
	encoded[m] = nil

	decoded, err := saeccDecode(encoded, m, outerN, outerK, kPerm, kECCPerm, kECCEnc)
	if err != nil {
		t.Fatalf("saeccDecode with parity erasure: %v", err)
	}
	if !blockEqual(decoded, blocks) {
		t.Fatal("saeccDecode: wrong result after parity erasure")
	}
}

// TestSAECCDecodeWithMessageErasure verifies that saeccDecode recovers a
// message block that was erased, using the RS parity blocks.
func TestSAECCDecodeWithMessageErasure(t *testing.T) {
	kPerm := randomBlock(t, 32)
	kECCPerm := randomBlock(t, 32)
	kECCEnc := randomBlock(t, 32)
	outerN, outerK := 6, 4
	m := 8 // 2 stripes of 4

	blocks := randomBlocks(t, m, 32)
	encoded, err := saeccEncode(blocks, outerN, outerK, kPerm, kECCPerm, kECCEnc)
	if err != nil {
		t.Fatalf("saeccEncode: %v", err)
	}

	// Erase one message block. The SA-ECC permutation may place it in any
	// stripe; we erase block 0 which always exists.
	encoded[0] = nil

	decoded, err := saeccDecode(encoded, m, outerN, outerK, kPerm, kECCPerm, kECCEnc)
	if err != nil {
		t.Fatalf("saeccDecode with message erasure: %v", err)
	}
	if !blockEqual(decoded, blocks) {
		t.Fatal("saeccDecode: wrong result after message block erasure")
	}
}

// ---------------------------------------------------------------------------
// Extract protocol tests
// ---------------------------------------------------------------------------

// TestExtractHonestServer verifies that Extract recovers the original file
// exactly when the encoded file is intact (honest server case).
func TestExtractHonestServer(t *testing.T) {
	mk, ef, original := encodeFile(t, defaultParams(), 12)

	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Extract: recovered file does not match original")
	}
}

// TestExtractShortFile verifies extraction for a file whose size is not a
// multiple of OuterK (exercises the short last stripe code path).
func TestExtractShortFile(t *testing.T) {
	mk, ef, original := encodeFile(t, defaultParams(), 9) // 9 blocks, OuterK=4 → short last stripe

	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Extract: recovered file does not match original (short last stripe)")
	}
}

// TestExtractWithParityErasures verifies that Extract recovers the file when
// some parity blocks are set to nil (simulating known corruptions).
// OuterN=6, OuterK=4 → 2 parity per stripe; erasing 1 parity per stripe is within capacity.
func TestExtractWithParityErasures(t *testing.T) {
	mk, ef, original := encodeFile(t, defaultParams(), 8)

	// Erase one parity block per stripe.  With m=8, OuterK=4 there are 2 stripes
	// and 2 parity blocks each (positions m+0, m+1, m+2, m+3 in ef.Blocks).
	ef.Blocks[ef.NumMessage+0] = nil
	ef.Blocks[ef.NumMessage+2] = nil

	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Extract with parity erasures: %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Extract: recovered file does not match original after parity erasures")
	}
}

// TestExtractWithMessageErasure verifies that Extract recovers the original
// file when one message block (data block) is set to nil.
func TestExtractWithMessageErasure(t *testing.T) {
	mk, ef, original := encodeFile(t, defaultParams(), 8)

	// Erase one message block.
	ef.Blocks[0] = nil

	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Extract with message erasure: %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Extract: recovered file does not match original after message block erasure")
	}
}

// TestExtractMACVerification verifies that Extract returns an error when the
// recovered file does not match the stored MAC.
//
// Corrupting all message blocks (non-nil, so not treated as erasures) causes
// rsDecodeBlocks to return them as-is via the systematic fast path, producing a
// wrong recovered file. Re-encoding that wrong file yields different parity, so
// the MAC comparison against ef.FileMAC fails.
func TestExtractMACVerification(t *testing.T) {
	mk, ef, _ := encodeFile(t, defaultParams(), 8)

	// Replace every message block with random bytes. These are non-nil so they
	// are not treated as erasures; the decoder accepts them as-is.
	for i := range ef.NumMessage {
		ef.Blocks[i] = randomBlock(t, 32)
	}

	_, err := Extract(mk, ef)
	if err == nil {
		t.Fatal("Extract: expected MAC verification error for corrupted file, got nil")
	}
}

// TestExtractAfterFullChallengeGame exercises Extract after a complete
// challenge-response Phase I, confirming the two phases are compatible.
func TestExtractAfterFullChallengeGame(t *testing.T) {
	params := defaultParams()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatal(err)
	}
	original := randomBlocks(t, 12, 32)
	ef, err := Encode(mk, original)
	if err != nil {
		t.Fatal(err)
	}

	// Phase I: verify all Q sentinels.
	for j := 1; j <= params.Q; j++ {
		chal, _ := MakeChallenge(mk, j)
		resp, _ := Respond(ef, chal)
		ok, err := Verify(mk, chal, resp)
		if err != nil || !ok {
			t.Fatalf("Phase I challenge j=%d failed: ok=%v err=%v", j, ok, err)
		}
	}

	// Phase II: extract the file.
	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Phase II Extract: %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Phase II Extract: recovered file does not match original")
	}
}

// ---------------------------------------------------------------------------
// Phase I tests: RespondExtract, solveInnerCode, extractPhaseI
// ---------------------------------------------------------------------------

// phaseIParams returns params with Alpha=10, Delta=0.25, P=2^31-1.
// Blocks must be 3 bytes so that SetBytes(block) < P (§ P > max(block value)).
func phaseIParams() *Params {
	return &Params{
		V:      3,
		W:      10,
		Q:      5,
		P:      big.NewInt(2147483647),
		OuterN: 6,
		OuterK: 4,
		Alpha:  10,
		Delta:  0.25,
	}
}

// TestRespondExtractDeterministic verifies that RespondExtract is deterministic:
// the same (ef, seed, u) always returns the same bytes.
func TestRespondExtractDeterministic(t *testing.T) {
	params := phaseIParams()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	blocks := randomBlocks(t, 12, 3) // 3-byte blocks fit in Z_P = 2^31-1
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	seed := randomBlock(t, 32)
	r1, err := RespondExtract(ef, seed, 1)
	if err != nil {
		t.Fatalf("RespondExtract: %v", err)
	}
	r2, err := RespondExtract(ef, seed, 1)
	if err != nil {
		t.Fatalf("RespondExtract: %v", err)
	}
	if !bytes.Equal(r1, r2) {
		t.Fatal("RespondExtract not deterministic for the same inputs")
	}
}

// TestRespondExtractDifferentColumns verifies that different u values produce
// different responses (with overwhelming probability), matching the inner code
// property that distinct generator columns are linearly independent.
func TestRespondExtractDifferentColumns(t *testing.T) {
	params := phaseIParams()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	blocks := randomBlocks(t, 12, 3)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	seed := randomBlock(t, 32)

	r1, _ := RespondExtract(ef, seed, 1)
	r2, _ := RespondExtract(ef, seed, 2)
	if bytes.Equal(r1, r2) {
		t.Fatal("RespondExtract: u=1 and u=2 produced the same response (negligible probability)")
	}
}

// TestRespondExtractRangeCheck verifies that RespondExtract rejects u values
// outside [1, W].
func TestRespondExtractRangeCheck(t *testing.T) {
	params := phaseIParams()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	blocks := randomBlocks(t, 8, 3)
	ef, err := Encode(mk, blocks)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	seed := randomBlock(t, 32)

	if _, err := RespondExtract(ef, seed, 0); err == nil {
		t.Fatal("expected error for u=0, got nil")
	}
	if _, err := RespondExtract(ef, seed, params.W+1); err == nil {
		t.Fatalf("expected error for u=%d (W+1), got nil", params.W+1)
	}
	if _, err := RespondExtract(ef, seed, params.W); err != nil {
		t.Fatalf("u=W should be valid, got error: %v", err)
	}
}

// TestSolveInnerCodeRoundTrip verifies that solveInnerCode recovers the exact
// field elements used to build the responses.
//
// Constructs v random field elements F[0..v-1] ∈ Z_P, computes W responses
// M[u] = Σ_{s=1}^v F[s] · G[s][u] mod P by calling computeInnerResponse with
// synthetic single-element blocks, then checks that solveInnerCode returns F.
func TestSolveInnerCodeRoundTrip(t *testing.T) {
	P := big.NewInt(2147483647)
	gseed := randomBlock(t, 32)
	v, w := 4, 10

	// Build v blocks whose SetBytes value mod P equals a known field element.
	// Use 3-byte blocks so the value fits in Z_P without truncation.
	fieldElems := make([]*big.Int, v)
	blocks := make([][]byte, v)
	for s := range v {
		fe, _ := big.NewInt(0).SetString("1000000", 10) // deterministic, non-trivial
		fe.Add(fe, big.NewInt(int64(s*999983)))
		fe.Mod(fe, P)
		fieldElems[s] = fe
		b := fe.Bytes()
		block := make([]byte, 3)
		copy(block[3-len(b):], b) // right-aligned in 3 bytes
		blocks[s] = block
	}
	indices := make([]int, v)
	for s := range v {
		indices[s] = s
	}

	responses := make([]*big.Int, w)
	for u := 1; u <= w; u++ {
		responses[u-1] = computeInnerResponse(blocks, indices, gseed, u, P)
	}

	recovered, err := solveInnerCode(gseed, responses, v, P)
	if err != nil {
		t.Fatalf("solveInnerCode: %v", err)
	}
	for s := range v {
		if recovered[s].Cmp(fieldElems[s]) != 0 {
			t.Fatalf("element %d: got %v, want %v", s, recovered[s], fieldElems[s])
		}
	}
}

// TestSolveInnerCodeTooFewResponses verifies that solveInnerCode returns an
// error when fewer than v responses are provided.
func TestSolveInnerCodeTooFewResponses(t *testing.T) {
	P := big.NewInt(2147483647)
	gseed := randomBlock(t, 32)
	v := 4

	responses := make([]*big.Int, v-1)
	for i := range v - 1 {
		responses[i] = big.NewInt(0)
	}
	_, err := solveInnerCode(gseed, responses, v, P)
	if err == nil {
		t.Fatal("expected error for too few responses, got nil")
	}
}

// TestExtractPhaseIHonest verifies that Extract with Alpha>0 (Phase I + Phase II)
// recovers the original file when the server is honest.
//
// Uses 3-byte blocks so that SetBytes(block) < P = 2^31-1.
func TestExtractPhaseIHonest(t *testing.T) {
	params := phaseIParams()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	original := randomBlocks(t, 12, 3)
	ef, err := Encode(mk, original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Extract (Phase I+II): %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Extract (Phase I+II): recovered file does not match original")
	}
}

// TestExtractPhaseIShortFile verifies Phase I + Phase II extraction for a file
// whose block count is not a multiple of OuterK (short last stripe path).
func TestExtractPhaseIShortFile(t *testing.T) {
	params := phaseIParams()
	mk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	original := randomBlocks(t, 9, 3) // OuterK=4 → last stripe has 1 block
	ef, err := Encode(mk, original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	recovered, err := Extract(mk, ef)
	if err != nil {
		t.Fatalf("Extract (Phase I+II, short file): %v", err)
	}
	if !blockEqual(recovered, original) {
		t.Fatal("Extract (Phase I+II): recovered file does not match original (short last stripe)")
	}
}
