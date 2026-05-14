// Package suite defines the Suite type that bundles the cryptographic
// primitives shared by the PDP and POR schemes: block hashing, QR_N hashing,
// PRF, and PRP construction. Call SuiteByID to look up a registered suite by
// its numeric identifier, or use SuiteV1, SuiteV2, or SuiteV3 directly.
package suite

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"lukechampine.com/blake3"
)

// Suite bundles the cryptographic primitives that govern block selection and
// coefficient generation. These primitives are shared by the Ateniese S-PDP
// scheme, the Erway DPDP I scheme, and the BJ-POR construction — any scheme
// that needs a PRP for block selection or a PRF for coefficient derivation
// should reference a Suite rather than hard-coding a specific hash construction.
//
// The numeric ID is stored in every ateniese.Tag so that proof operations can
// confirm all tags share the same algorithm.
//
// HashToQRN is used by the Ateniese scheme's tag and verification operations;
// schemes that do not use RSA-based tags can ignore this field.
//
// Obtain a Suite via one of the package-level variables (SuiteV1, …) rather
// than constructing one directly.
type Suite struct {
	id uint8

	// HashBlock maps raw block bytes to a *big.Int exponent, used in both
	// tagging and proof accumulation. Schemes that use g^{H(block)} mod N
	// (Ateniese, Erway) call this to convert arbitrary-length block data to a
	// fixed-width integer; the deviation from paper notation is documented in
	// each scheme's package doc.
	HashBlock func(data []byte) *big.Int

	// HashToQRN maps an arbitrary byte string to a near-uniform element of
	// QR_N. Used by the Ateniese scheme in TagBlock and CheckProof.
	HashToQRN func(data []byte, N *big.Int) *big.Int

	// PRF is a keyed pseudorandom function. A single index call produces the
	// per-block coefficient a_j used in PDP. A two-index call PRF(key, u, s)
	// folds u into the HMAC input before s, providing domain separation for
	// multi-dimensional applications such as the BJ-POR inner-code matrix
	// G[s][u] = PRF(GSeed, u, s).
	PRF func(key []byte, js ...int) *big.Int

	// BuildPRP constructs a pseudorandom permutation of [0, n) from key.
	// Called with the same key and n by both GenProof and CheckProof.
	BuildPRP func(key []byte, n int) []int
}

// ID returns the suite's numeric version identifier, suitable for storage in
// serialized Tags and Proofs.
func (s *Suite) ID() uint8 { return s.id }

var suiteRegistry = map[uint8]*Suite{}

// SuiteByID returns the Suite registered under id, or (nil, false) if no suite
// with that ID is known. Used by servers to dispatch proof operations to the
// correct algorithm based on the SuiteID embedded in incoming tags.
func SuiteByID(id uint8) (*Suite, bool) {
	s, ok := suiteRegistry[id]
	return s, ok
}

func registerSuite(s *Suite) *Suite {
	if _, exists := suiteRegistry[s.id]; exists {
		panic(fmt.Sprintf("suite: duplicate suite ID %d", s.id))
	}
	suiteRegistry[s.id] = s
	return s
}

// Suite primitive usage by scheme:
//
//	Primitive   ateniese   erway   bjo   sw
//	─────────   ────────   ─────   ───   ──
//	HashBlock      ✓         ✓
//	HashToQRN      ✓         ✓
//	PRF            ✓         ✓      ✓     ✓
//	BuildPRP       ✓         ✓      ✓
//
// bjo and sw ignore HashBlock and HashToQRN entirely. The suite choice for
// those schemes reduces to PRF algorithm only.
//
// All three suites produce 256-bit PRF output, bounding statistical bias when
// reducing mod P to P/2^256 ≤ 2^{-128} for any P ≤ 2^128. This is the
// minimum required for sw, whose sector prime P can reach 2^128.
//
//	Suite    PRF primitive        Notes
//	──────   ─────────────────    ──────────────────────────────────────────────
//	SuiteV1  HMAC-SHA256          Conservative default; FIPS-compatible, portable
//	SuiteV2  AES-256-CTR          ~10× faster PRF on hardware with AES-NI
//	SuiteV3  BLAKE3 keyed hash    Fast in pure software; no special hardware
//
// Recommended defaults: sw → SuiteV1 (most conservative PRF for the scheme
// that relies on PRF uniformity most heavily). bjo → SuiteV2 or SuiteV3
// (PRF is called O(W·n) times for the inner-code matrix; speed matters).
// ateniese/erway → any suite; RSA exponentiations dominate, PRF cost is noise.

// SuiteV1 is the conservative baseline suite using HMAC-SHA256 throughout.
//
//   - HashBlock:  SHA-256 → 256-bit *big.Int
//   - HashToQRN: MGF1-SHA256 (RFC 8017 §B.2.1), bias < 2^{-128}
//   - PRF:       HMAC-SHA256, full 256-bit output
//   - BuildPRP:  sort-by-HMAC-SHA256
//
// Acceptable for: all schemes. Recommended default for sw.
var SuiteV1 = registerSuite(&Suite{
	id:        1,
	HashBlock: sha256HashBlock,
	HashToQRN: mgf1SHA256HashToQRN,
	PRF:       hmacSHA256PRF256,
	BuildPRP:  hmacSHA256PRP,
})

// SuiteV2 replaces HMAC-SHA256 in the PRF with AES-256 in counter mode.
// On processors with hardware AES-NI the PRF is roughly 10× faster than
// SuiteV1, which directly benefits ateniese GenProof and erway Prove (one PRF
// call per challenged block) and bjo inner-code generation (O(W·n) PRF calls).
// HashBlock and HashToQRN remain SHA-256 based and are unused by bjo and sw.
//
//   - HashBlock:  SHA-256 → 256-bit *big.Int
//   - HashToQRN: MGF1-SHA256
//   - PRF:       AES-256-CTR, 256-bit output
//   - BuildPRP:  sort-by-HMAC-SHA256
//
// Acceptable for: all schemes. Recommended for bjo on AES-NI hardware.
var SuiteV2 = registerSuite(&Suite{
	id:        2,
	HashBlock: sha256HashBlock,
	HashToQRN: mgf1SHA256HashToQRN,
	PRF:       aesCTRPRF256,
	BuildPRP:  hmacSHA256PRP,
})

// SuiteV3 uses BLAKE3 throughout, replacing SHA-256 in HashBlock and HashToQRN
// and using BLAKE3's keyed-hash mode for the PRF. BLAKE3 is fast in pure
// software (no special hardware required) and supports variable-length output
// natively, avoiding the MGF1 counter loop needed for SHA-256.
//
// Note: bjo and sw do not call HashBlock or HashToQRN; for those schemes the
// suite choice reduces to the PRF algorithm.
//
//   - HashBlock:  BLAKE3-256
//   - HashToQRN: BLAKE3 XOF (variable-length output, bias < 2^{-128})
//   - PRF:       BLAKE3 keyed hash, 256-bit output
//   - BuildPRP:  sort-by-HMAC-SHA256
//
// Acceptable for: all schemes. Recommended for bjo on platforms without AES-NI.
var SuiteV3 = registerSuite(&Suite{
	id:        3,
	HashBlock: blake3HashBlock,
	HashToQRN: blake3HashToQRN,
	PRF:       blake3PRF256,
	BuildPRP:  hmacSHA256PRP,
})

// sha256HashBlock maps raw block bytes to a *big.Int via SHA-256.
func sha256HashBlock(data []byte) *big.Int {
	h := sha256.Sum256(data)
	return new(big.Int).SetBytes(h[:])
}

// mgf1SHA256HashToQRN maps an arbitrary byte string deterministically and
// near-uniformly into QR_N using MGF1 (RFC 8017 §B.2.1) with SHA-256.
//
// Per footnote 3 of the Ateniese paper, h is constructed by squaring the output
// of a full-domain hash over [0, N-1]. Generating ⌈(N.BitLen()+128)/8⌉ bytes
// before reducing mod N bounds the statistical bias to < 2^{-128}.
func mgf1SHA256HashToQRN(data []byte, N *big.Int) *big.Int {
	targetBytes := (N.BitLen() + 128 + 7) / 8
	var buf []byte
	for counter := uint32(0); len(buf) < targetBytes; counter++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h := sha256.New()
		h.Write(data)
		h.Write(c[:])
		buf = append(buf, h.Sum(nil)...)
	}
	x := new(big.Int).SetBytes(buf[:targetBytes])
	x.Mod(x, N)
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return new(big.Int).Exp(x, big.NewInt(2), N)
}

// hmacSHA256PRF256 is a 256-bit pseudorandom function based on HMAC-SHA-256.
//
// A single argument PRF(key, j) encodes j as a big-endian uint64. Multiple
// arguments fold each into the MAC in order (used by BJ-POR's inner-code
// matrix G[s][u] = PRF(GSeed, u, s) for domain separation).
func hmacSHA256PRF256(key []byte, js ...int) *big.Int {
	buf := make([]byte, 8)
	mac := hmac.New(sha256.New, key)
	for _, j := range js {
		binary.BigEndian.PutUint64(buf, uint64(j))
		mac.Write(buf)
	}
	return new(big.Int).SetBytes(mac.Sum(nil)) // full 256-bit output
}

// aesCTRPRF256 is a 256-bit PRF built on AES-256 in counter mode.
//
// The PRF key is expanded to 32 bytes via SHA-256 to satisfy AES-256's
// fixed-length key requirement. Index arguments are encoded as big-endian
// uint64s into the 16-byte CTR nonce (up to two fit in one AES block);
// AES-CTR then generates 32 bytes (two blocks) of keystream as output.
//
// On processors with AES-NI this is roughly 10× faster than hmacSHA256PRF256.
// Note: AES key schedule is performed per call; a future optimisation could
// pre-schedule once when the key is stable across many calls.
func aesCTRPRF256(key []byte, js ...int) *big.Int {
	aesKey := sha256.Sum256(key) // fixed 32-byte key for AES-256
	nonce := make([]byte, aes.BlockSize)
	for i, j := range js {
		if i >= 2 {
			break
		}
		binary.BigEndian.PutUint64(nonce[i*8:], uint64(j))
	}
	ciph, _ := aes.NewCipher(aesKey[:]) // always succeeds: key is 32 bytes
	stream := cipher.NewCTR(ciph, nonce)
	out := make([]byte, 32)
	stream.XORKeyStream(out, out)
	return new(big.Int).SetBytes(out)
}

// blake3HashBlock maps raw block bytes to a *big.Int via BLAKE3-256.
func blake3HashBlock(data []byte) *big.Int {
	h := blake3.Sum256(data)
	return new(big.Int).SetBytes(h[:])
}

// blake3HashToQRN maps an arbitrary byte string near-uniformly into QR_N
// using BLAKE3's native variable-length output (XOF mode). Generating
// ⌈(N.BitLen()+128)/8⌉ bytes bounds statistical bias to < 2^{-128}.
func blake3HashToQRN(data []byte, N *big.Int) *big.Int {
	targetBytes := (N.BitLen() + 128 + 7) / 8
	h := blake3.New(targetBytes, nil)
	h.Write(data)
	buf := h.Sum(nil)
	x := new(big.Int).SetBytes(buf)
	x.Mod(x, N)
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return new(big.Int).Exp(x, big.NewInt(2), N)
}

// blake3PRF256 is a 256-bit PRF built on BLAKE3's keyed-hash mode.
//
// The PRF key is expanded to 32 bytes via BLAKE3-256 (the keyed-hash API
// requires exactly 32 bytes). Index arguments are encoded as big-endian
// uint64s and written into the hasher in order.
func blake3PRF256(key []byte, js ...int) *big.Int {
	k32 := blake3.Sum256(key) // key derivation to 32-byte BLAKE3 key
	h := blake3.New(32, k32[:])
	buf := make([]byte, 8)
	for _, j := range js {
		binary.BigEndian.PutUint64(buf, uint64(j))
		h.Write(buf)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// hmacSHA256PRP constructs a pseudorandom permutation of [0, n) keyed by key.
// It assigns each index i an HMAC-SHA-256 score and sorts by score, producing
// a deterministic permutation that both client and server can reconstruct
// from the same challenge key K1 without communicating the indices directly.
func hmacSHA256PRP(key []byte, n int) []int {
	type entry struct {
		index int
		score []byte
	}
	entries := make([]entry, n)
	for i := range n {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(i))
		mac := hmac.New(sha256.New, key)
		mac.Write(buf)
		entries[i] = entry{index: i, score: mac.Sum(nil)}
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].score, entries[j].score) < 0
	})
	perm := make([]int, n)
	for i := range n {
		perm[i] = entries[i].index
	}
	return perm
}
