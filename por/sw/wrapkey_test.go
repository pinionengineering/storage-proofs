package sw

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/suite"
)

func testWrapParams() *Params {
	p, _ := new(big.Int).SetString("340282366920938463463374607431768211507", 10)
	return &Params{S: 3, P: p}
}

func testIDs(n int) [][]byte {
	ids := make([][]byte, n)
	for i := range ids {
		ids[i] = blocks.IntID(i)
	}
	return ids
}

// TestSealOpenFileTag_RoundTrip confirms OpenFileTag recovers exactly the
// SecretKey SealFileTag generated, and that the recovered key works
// end-to-end through the existing, unchanged TagBlocks/MakeChallenge/
// RespondFetch/Verify flow (§3.2 Priv.St then Priv.V, with the audit
// protocol from §3 in between).
func TestSealOpenFileTag_RoundTrip(t *testing.T) {
	params := testWrapParams()
	wrapKey, err := WrapKeyGen(params)
	if err != nil {
		t.Fatalf("WrapKeyGen: %v", err)
	}

	ids := testIDs(10)
	sk, tag, err := SealFileTag(wrapKey, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}

	recovered, err := OpenFileTag(wrapKey, tag, ids)
	if err != nil {
		t.Fatalf("OpenFileTag: %v", err)
	}
	if string(recovered.K) != string(sk.K) {
		t.Fatalf("K mismatch: got %x, want %x", recovered.K, sk.K)
	}
	if len(recovered.Alpha) != len(sk.Alpha) {
		t.Fatalf("Alpha length mismatch: got %d, want %d", len(recovered.Alpha), len(sk.Alpha))
	}
	for j := range sk.Alpha {
		if recovered.Alpha[j].Cmp(sk.Alpha[j]) != 0 {
			t.Fatalf("Alpha[%d] mismatch: got %v, want %v", j, recovered.Alpha[j], sk.Alpha[j])
		}
	}

	// End-to-end: the recovered key must work exactly like the original
	// through the existing, unmodified protocol functions.
	// 15 bytes / 3 sectors = 5-byte sectors (40 bits), comfortably under
	// testWrapParams's ~129-bit P; see ValidateP for the constraint.
	blockContents := make([][]byte, len(ids))
	for i := range blockContents {
		b := make([]byte, 15)
		rand.Read(b)
		blockContents[i] = b
	}
	store, err := blocks.NewMapStore(ids, blockContents)
	if err != nil {
		t.Fatalf("NewMapStore: %v", err)
	}
	tags, err := TagBlocks(suite.SuiteV1, sk, store)
	if err != nil {
		t.Fatalf("TagBlocks: %v", err)
	}
	tagMap := make(map[int]*Tag, len(tags))
	for i, tg := range tags {
		tagMap[i] = tg
	}
	chal, err := MakeChallenge(ids, params, 4)
	if err != nil {
		t.Fatalf("MakeChallenge: %v", err)
	}
	proof, err := RespondFetch(params, tagMap, chal, store)
	if err != nil {
		t.Fatalf("RespondFetch: %v", err)
	}
	ok, err := Verify(suite.SuiteV1, recovered, ids, chal, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify rejected a valid proof using the recovered SecretKey")
	}
}

// TestSealFileTag_FreshPerCall confirms two SealFileTag calls for the same
// ids under the same WrapKey produce independent (K, Alpha) pairs -- §3.2
// Priv.St is run once per file, never reused across files.
func TestSealFileTag_FreshPerCall(t *testing.T) {
	wrapKey, err := WrapKeyGen(testWrapParams())
	if err != nil {
		t.Fatalf("WrapKeyGen: %v", err)
	}
	ids := testIDs(5)

	sk1, _, err := SealFileTag(wrapKey, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}
	sk2, _, err := SealFileTag(wrapKey, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}
	if string(sk1.K) == string(sk2.K) {
		t.Fatal("two SealFileTag calls produced the same K")
	}
	same := true
	for j := range sk1.Alpha {
		if sk1.Alpha[j].Cmp(sk2.Alpha[j]) != 0 {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two SealFileTag calls produced identical Alpha vectors")
	}
}

// TestOpenFileTag_TamperedCiphertextRejected confirms GCM's authentication
// catches a flipped ciphertext byte before any plaintext is returned.
func TestOpenFileTag_TamperedCiphertextRejected(t *testing.T) {
	wrapKey, _ := WrapKeyGen(testWrapParams())
	ids := testIDs(5)
	_, tag, err := SealFileTag(wrapKey, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}
	tag.Ciphertext[0] ^= 0xFF

	if _, err := OpenFileTag(wrapKey, tag, ids); err == nil {
		t.Fatal("OpenFileTag accepted a tampered ciphertext")
	}
}

// TestOpenFileTag_TamperedNonceRejected mirrors the ciphertext tamper test
// for the nonce: GCM's authentication covers the nonce implicitly through
// the AEAD construction, so a wrong nonce must also fail to decrypt (not
// silently produce garbage plaintext).
func TestOpenFileTag_TamperedNonceRejected(t *testing.T) {
	wrapKey, _ := WrapKeyGen(testWrapParams())
	ids := testIDs(5)
	_, tag, err := SealFileTag(wrapKey, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}
	tag.Nonce[0] ^= 0xFF

	if _, err := OpenFileTag(wrapKey, tag, ids); err == nil {
		t.Fatal("OpenFileTag accepted a tampered nonce")
	}
}

// TestOpenFileTag_WrongWrapKeyRejected confirms a FileTag sealed under one
// WrapKey cannot be opened under a different one.
func TestOpenFileTag_WrongWrapKeyRejected(t *testing.T) {
	params := testWrapParams()
	wrapKeyA, _ := WrapKeyGen(params)
	wrapKeyB, _ := WrapKeyGen(params)
	ids := testIDs(5)

	_, tag, err := SealFileTag(wrapKeyA, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}

	if _, err := OpenFileTag(wrapKeyB, tag, ids); err == nil {
		t.Fatal("OpenFileTag accepted a FileTag sealed under a different WrapKey")
	}
}

// TestOpenFileTag_SwappedIDsRejected is the core security property this
// mechanism adds beyond the paper's own single-file model: a FileTag sealed
// for one file's ids must not open against a different file's ids, even
// under the correct WrapKey. Without this, a dishonest storage provider
// holding several FileTags sealed under the same WrapKey could swap two
// files' tags undetected.
func TestOpenFileTag_SwappedIDsRejected(t *testing.T) {
	wrapKey, err := WrapKeyGen(testWrapParams())
	if err != nil {
		t.Fatalf("WrapKeyGen: %v", err)
	}
	idsA := testIDs(5)
	idsB := [][]byte{blocks.IntID(100), blocks.IntID(101), blocks.IntID(102)}

	_, tagA, err := SealFileTag(wrapKey, idsA)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}

	if _, err := OpenFileTag(wrapKey, tagA, idsB); err == nil {
		t.Fatal("OpenFileTag opened file A's tag against file B's ids")
	}
}

// TestOpenFileTag_ReorderedIDsRejected confirms the ids binding is sensitive
// to order, not just set membership -- swapping two positions changes which
// block each challenged index refers to, so it must be treated as a
// different file.
func TestOpenFileTag_ReorderedIDsRejected(t *testing.T) {
	wrapKey, err := WrapKeyGen(testWrapParams())
	if err != nil {
		t.Fatalf("WrapKeyGen: %v", err)
	}
	ids := testIDs(5)
	_, tag, err := SealFileTag(wrapKey, ids)
	if err != nil {
		t.Fatalf("SealFileTag: %v", err)
	}

	reordered := append([][]byte{}, ids...)
	reordered[0], reordered[1] = reordered[1], reordered[0]

	if _, err := OpenFileTag(wrapKey, tag, reordered); err == nil {
		t.Fatal("OpenFileTag accepted a reordered ids list")
	}
}

// TestIDsDigest_NoConcatenationAmbiguity confirms two different id lists
// that would concatenate to the same bytes without length-prefixing
// (["ab","c"] vs ["a","bc"]) produce different digests.
func TestIDsDigest_NoConcatenationAmbiguity(t *testing.T) {
	a := idsDigest([][]byte{[]byte("ab"), []byte("c")})
	b := idsDigest([][]byte{[]byte("a"), []byte("bc")})
	if string(a) == string(b) {
		t.Fatal("idsDigest collided across differently-split id lists with identical concatenation")
	}
}
