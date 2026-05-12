// Package por implements the improved Juels-Kaliski Proof of Retrievability (POR)
// protocol from the paper "Proofs of Retrievability: Theory and Implementation"
// by Bowers, Juels, and Oprea (RSA Laboratories).
// A copy of the paper is in doc/proofs-of-retrievability.pdf.
//
// # Overview
//
// A POR lets a client (V) verify probabilistically that a remote server (P)
// stores a file F intact and can retrieve it. Unlike PDP, a POR provides an
// extractor: V can fully recover F from a server that answers a sufficient
// fraction of challenges correctly.
//
// The protocol is the JK variant from §4.2.1 with six functions:
//
//  1. KeyGen[π] → MK: Generate a master secret key and derive all sub-keys.
//
//  2. Encode(F; MK)[π] → F̃: Apply the outer systematic adversarial ECC (SA-ECC)
//     to F, then precompute q encrypted sentinel values Q_1,...,Q_q. Upload F̃
//     (encoded blocks + sentinels + file MAC) to P. V retains only MK.
//
//  3. Challenge(j; MK) → c: Build c = (j, k_j^c, u) where j ∈ [1,Q] selects a
//     sentinel, k_j^c is the per-challenge PRF key for deriving v block indices,
//     and u ∈ [1,W] is the inner code generator column index.
//
//  4. Respond(c, F̃) → (M_j, Q_j): Server uses k_j^c to derive block indices
//     i_1,...,i_v and computes (§4.2.1):
//
//	    M_j = Σ_{s=1}^v SHA256(F̃_{i_s}) · G[s][u]  mod P
//
//     G[s][u] is the inner code generator matrix element derived from GSeed
//     (see Inner code section). The server also returns Q_j, the pre-stored
//     encrypted sentinel for challenge j.
//
//  5. Verify(c, (M_j, Q_j); MK) → {0,1}: Decrypt Q_j with k_j^e and check
//     M_j == Dec(k_j^e, Q_j).
//
//  6. Extract: Not implemented; described in §3.3.2. The client submits α·t/v
//     challenges and majority-decodes each of the t encoded file blocks, then
//     applies the outer SA-ECC decoder to recover F.
//
// # Relationship to pdp
//
// This package builds on the pdp package. The pseudorandom permutation (PRP)
// used for SA-ECC stripe assignment and parity ordering reuses pdp.SuiteV1.BuildPRP
// (HMAC-SHA256 sort-by-score). The pseudorandom function (PRF) used to derive
// inner code generator elements reuses pdp.SuiteV1.PRF (HMAC-SHA256 truncated
// to 128 bits) with two indices: G[s][u] = PRF(GSeed, u, s) mod P. The
// GF(2^8) arithmetic and Reed-Solomon outer code are new.
//
// # Inner code (ECCin)
//
// The inner code is a linear code over Z_P (§4.2.1). Its generator matrix
// G[s][u] is derived from the public parameter GSeed via two applications of
// the pdp PRF: a per-u key ku = PRF(GSeed, u), then G[s][u] = PRF(ku, s) mod P.
// The response to challenge (i_1,...,i_v, u) is:
//
//	M = Σ_{s=1}^v SHA256(F̃_{i_s}) · G[s][u]  mod P
//
// Linearity in block content is the key algebraic invariant of the protocol;
// it is verified in math_test.go.
//
// # Outer code (SA-ECC)
//
// The systematic adversarial ECC (§4.2) encodes F as follows:
//  1. Permute file block indices with PRP(KPerm) (via pdp.SuiteV1.BuildPRP) to
//     assign stripes without reordering the stored blocks.
//  2. Reed-Solomon encode each stripe of OuterK blocks into OuterN blocks over
//     GF(2^8), yielding OuterN-OuterK parity blocks per stripe.
//  3. Permute all parity blocks with PRP(KECCPerm) and encrypt each independently
//     with KECCEnc (AES-256-CTR; block-level independence needed for extraction).
//  4. Output F unchanged followed by the scrambled parity blocks.
//
// The original file blocks are stored first (systematic code), so the client
// need not decrypt anything in the common honest-server case.
//
// # Deviations from the paper
//
// Block-to-field mapping: blocks are SHA-256 hashed before use as Z_P elements
// (the paper treats blocks as fixed-size symbols fitting directly in Z_P; hashing
// is necessary for arbitrary-length blocks and is applied consistently in both
// Encode and Respond).
//
// Key derivation: sub-keys are derived from a random master secret using
// HMAC-SHA-256 with distinct labels (the paper leaves the KDF unspecified).
//
// Generator matrix: G[s][u] = PRF(GSeed, u, s) mod P uses the extended pdp PRF
// rather than being a fixed system parameter, allowing a fresh G per deployment.
//
// Sentinel encryption: AES-256-GCM with a deterministic nonce derived from k_j^e
// (the paper specifies IND-CPA symmetric encryption; GCM also provides
// authentication, which strengthens the verification check).
package por

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/pinionengineering/storage-proofs/pdp"
)

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic
// ---------------------------------------------------------------------------

// GF(2^8) uses the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
// Multiplication is implemented via precomputed exp/log tables with generator g=2.
// These tables are used only by the Reed-Solomon outer code.

var (
	// gfExp[i] = 2^i in GF(256) for i ∈ [0, 511); index arithmetic uses mod 255.
	gfExp [512]byte
	// gfLog[x] = i such that 2^i = x; gfLog[0] is undefined (never accessed).
	gfLog [256]int
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = i
		// Multiply by g=0x03 (x+1), the primitive element of GF(2^8) with polynomial
		// 0x11b (AES spec). g*x = xtime(x) XOR x, where xtime is multiplication by {02}.
		old := x
		if x&0x80 != 0 {
			x = (x << 1) ^ 0x1b
		} else {
			x <<= 1
		}
		x ^= old // complete {03}*x = {02}*x XOR x
	}
	// Duplicate so gfExp[a+b] works without taking mod when a,b < 255.
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfAdd adds two GF(256) elements (XOR, same as subtraction in characteristic 2).
func gfAdd(a, b byte) byte { return a ^ b }

// gfMul multiplies two GF(256) elements using precomputed log/exp tables.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv returns the multiplicative inverse of a in GF(256). Panics for a=0.
func gfInv(a byte) byte {
	if a == 0 {
		panic("por: GF(256) inverse of 0")
	}
	return gfExp[255-int(gfLog[a])]
}

// gfPow returns a^n in GF(256).
func gfPow(a byte, n int) byte {
	if n == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])*n)%255]
}

// ---------------------------------------------------------------------------
// Reed-Solomon (systematic) over GF(2^8)
// ---------------------------------------------------------------------------

// rsEncodeSlice encodes a k-symbol message into an n-symbol systematic RS codeword
// over GF(2^8).
//
// The first k output symbols equal the message (systematic property).
// Parity symbols are computed via Lagrange interpolation: find the unique
// polynomial p(x) of degree < k with p(i) = message[i] for i = 0,...,k-1,
// using evaluation points 0, 1, ..., n-1 as GF(256) elements. Set parity
// symbol j = p(j) for j = k,...,n-1.
//
// Requires n ≤ 256 (at most 256 distinct evaluation points in GF(256)).
// Runtime: O(k^2 · (n-k)), suitable for small to moderate k.
func rsEncodeSlice(message []byte, n int) []byte {
	k := len(message)
	codeword := make([]byte, n)
	copy(codeword[:k], message) // systematic: first k symbols equal message

	for j := k; j < n; j++ {
		xj := byte(j)
		sum := byte(0)
		for i := 0; i < k; i++ {
			xi := byte(i)
			// Lagrange basis L_i(xj) = Π_{m≠i} (xj-xm)/(xi-xm); XOR is subtraction in GF(2^8).
			num, den := byte(1), byte(1)
			for m := 0; m < k; m++ {
				if m == i {
					continue
				}
				xm := byte(m)
				num = gfMul(num, gfAdd(xj, xm))
				den = gfMul(den, gfAdd(xi, xm))
			}
			sum = gfAdd(sum, gfMul(message[i], gfMul(num, gfInv(den))))
		}
		codeword[j] = sum
	}
	return codeword
}

// rsEncodeBlocks encodes k blocks (each blockSize bytes) into n blocks using
// systematic Reed-Solomon applied independently to each byte position.
// Output blocks 0..k-1 equal the input blocks (systematic).
// Output blocks k..n-1 are RS parity blocks.
func rsEncodeBlocks(blocks [][]byte, n int) [][]byte {
	k := len(blocks)
	if k == 0 {
		return make([][]byte, n)
	}
	blockSize := len(blocks[0])

	result := make([][]byte, n)
	for i := range n {
		result[i] = make([]byte, blockSize)
		if i < k {
			copy(result[i], blocks[i])
		}
	}

	msg := make([]byte, k)
	for b := range blockSize {
		for i := range k {
			msg[i] = blocks[i][b]
		}
		codeword := rsEncodeSlice(msg, n)
		for i := k; i < n; i++ {
			result[i][b] = codeword[i]
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// deriveKey derives a 32-byte sub-key from master using HMAC-SHA-256 with label.
// Each label must be unique across sub-keys.
func deriveKey(master []byte, label string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// challengeKey derives the per-challenge PRF key k_j^c from KChal and j.
// The server uses k_j^c to derive the v block indices for challenge j.
func challengeKey(kchal []byte, j int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(j))
	mac := hmac.New(sha256.New, kchal)
	mac.Write(buf)
	return mac.Sum(nil)
}

// encryptionKey derives the per-challenge encryption key k_j^e from KEnc and j.
func encryptionKey(kenc []byte, j int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(j))
	mac := hmac.New(sha256.New, kenc)
	mac.Write(buf)
	return mac.Sum(nil)
}

// deriveU derives the inner code column index u ∈ [1, W] for challenge j
// from the index key KInd. u is included in the challenge sent to the server.
func deriveU(kind []byte, j, w int) int {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(j))
	mac := hmac.New(sha256.New, kind)
	mac.Write(buf)
	h := mac.Sum(nil)
	return int(binary.BigEndian.Uint32(h[:4]))%w + 1 // 1-indexed: result in [1, W]
}

// blockIndices derives v distinct block indices from [0, t) using challenge key
// kjc. Delegates to pdp.SuiteV1.BuildPRP (HMAC-SHA-256 sort-by-score) and
// returns the first v elements of the resulting permutation.
func blockIndices(kjc []byte, v, t int) []int {
	return pdp.SuiteV1.BuildPRP(kjc, t)[:v]
}

// ---------------------------------------------------------------------------
// Inner code generator matrix
// ---------------------------------------------------------------------------

// innerCodeElement computes G[s][u] = PRF(gseed, u, s) mod P.
//
// The two-argument PRF call folds u and s into the HMAC input as consecutive
// big-endian uint64 values: HMAC(gseed, encode(u) ‖ encode(s)). This gives
// independent outputs for every (u, s) pair with a single HMAC call, replacing
// the previous two-step derivation (PRF(PRF(gseed, u), s)).
//
// gseed is a public parameter; s and u are 1-indexed as in §4.2.1.
func innerCodeElement(gseed []byte, s, u int, P *big.Int) *big.Int {
	return new(big.Int).Mod(pdp.SuiteV1.PRF(gseed, u, s), P)
}

// computeInnerResponse computes M = Σ_{s=1}^v SHA256(blocks[indices[s-1]]) · G[s][u] mod P.
// This is the core computation in Respond (§4.2.1).
func computeInnerResponse(blocks [][]byte, indices []int, gseed []byte, u int, P *big.Int) *big.Int {
	M := big.NewInt(0)
	for s, idx := range indices {
		h := sha256.Sum256(blocks[idx])
		Fi := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), P)
		Gsu := innerCodeElement(gseed, s+1, u, P) // s+1: 0-based slice → 1-based paper index
		M.Add(M, new(big.Int).Mul(Fi, Gsu))
		M.Mod(M, P)
	}
	return M
}

// mToBytes encodes a Z_P element as a fixed-length big-endian byte slice whose
// length is (P.BitLen()+7)/8. Fixed length ensures Dec(Enc(M)) round-trips
// correctly even when M has leading zero bytes.
func mToBytes(M, P *big.Int) []byte {
	pLen := (P.BitLen() + 7) / 8
	b := M.Bytes()
	out := make([]byte, pLen)
	copy(out[pLen-len(b):], b)
	return out
}

// ---------------------------------------------------------------------------
// Symmetric encryption for sentinels and parity blocks
// ---------------------------------------------------------------------------

// sentinelEncrypt encrypts plaintext with AES-256-GCM using a deterministic
// nonce derived from kje. The nonce is safe to reuse only once per key; since
// kje = HMAC(KEnc, j) is unique per challenge j, nonce reuse cannot occur.
func sentinelEncrypt(kje, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kje)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(append(kje, []byte("sentinel-nonce")...))
	return gcm.Seal(nil, h[:gcm.NonceSize()], plaintext, nil), nil
}

// sentinelDecrypt decrypts a sentinel produced by sentinelEncrypt.
// Returns an error if the GCM authentication tag does not verify.
func sentinelDecrypt(kje, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kje)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(append(kje, []byte("sentinel-nonce")...))
	return gcm.Open(nil, h[:gcm.NonceSize()], ciphertext, nil)
}

// parityEncrypt encrypts a single parity block with AES-256-CTR using per-block
// key and nonce both derived from keccenc and blockIdx.
//
// Block-level key independence is required: a corruption in one parity block
// must not propagate to others during extraction (§6.3: "each parity block is
// encrypted separately"). CTR mode satisfies this; CBC does not.
func parityEncrypt(keccenc []byte, blockIdx int, plaintext []byte) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(blockIdx))

	kmac := hmac.New(sha256.New, keccenc)
	kmac.Write([]byte("key"))
	kmac.Write(buf)
	blockKey := kmac.Sum(nil) // 32 bytes → AES-256

	nmac := hmac.New(sha256.New, keccenc)
	nmac.Write([]byte("nonce"))
	nmac.Write(buf)
	nonce := nmac.Sum(nil)[:aes.BlockSize] // 16 bytes for CTR

	blk, err := aes.NewCipher(blockKey)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(blk, nonce).XORKeyStream(ct, plaintext)
	return ct, nil
}

// ---------------------------------------------------------------------------
// SA-ECC outer code
// ---------------------------------------------------------------------------

// saeccEncode applies the Systematic Adversarial ECC (SA-ECC, §4.2) to m blocks
// and returns the original blocks followed by (t-m) permuted encrypted parity
// blocks, where t = m + numStripes*(OuterN-OuterK) and numStripes = ⌈m/OuterK⌉.
//
// The output is systematic: result[0:m] equals blocks (the original file is
// unchanged), so an honest server can serve F without decryption.
//
// Security depends on three secrets:
//   - kPerm: hides which original blocks belong to which stripe (PRP via pdp)
//   - kECCPerm: hides which permuted-parity position each parity block occupies (PRP via pdp)
//   - kECCEnc: encrypts each parity block (AES-256-CTR)
func saeccEncode(blocks [][]byte, outerN, outerK int, kPerm, kECCPerm, kECCEnc []byte) ([][]byte, error) {
	m := len(blocks)
	if m == 0 {
		return nil, fmt.Errorf("por: cannot encode empty file")
	}
	blockSize := len(blocks[0])

	// Step 1: Assign block indices to stripes via PRP(kPerm).
	// perm[j] is the original block index at permuted position j.
	// Stripe s contains permuted positions s*outerK..(s+1)*outerK-1.
	perm := pdp.SuiteV1.BuildPRP(kPerm, m)

	numStripes := (m + outerK - 1) / outerK
	numParityPerStripe := outerN - outerK
	totalParity := numStripes * numParityPerStripe

	// Step 2: RS-encode each stripe and collect parity blocks.
	allParity := make([][]byte, 0, totalParity)
	for s := range numStripes {
		start := s * outerK
		end := start + outerK
		if end > m {
			end = m
		}
		stripeBlocks := make([][]byte, outerK)
		for j := start; j < end; j++ {
			stripeBlocks[j-start] = blocks[perm[j]]
		}
		// Zero-pad the last stripe if it is short.
		for j := end - start; j < outerK; j++ {
			stripeBlocks[j] = make([]byte, blockSize)
		}
		encoded := rsEncodeBlocks(stripeBlocks, outerN)
		allParity = append(allParity, encoded[outerK:]...)
	}

	// Step 3: Permute parity blocks with PRP(kECCPerm).
	parityPerm := pdp.SuiteV1.BuildPRP(kECCPerm, totalParity)
	permParity := make([][]byte, totalParity)
	for i, pi := range parityPerm {
		permParity[i] = allParity[pi]
	}

	// Step 4: Encrypt each permuted parity block with AES-256-CTR(kECCEnc).
	encParity := make([][]byte, totalParity)
	for i, p := range permParity {
		ep, err := parityEncrypt(kECCEnc, i, p)
		if err != nil {
			return nil, fmt.Errorf("por: encrypting parity block %d: %w", i, err)
		}
		encParity[i] = ep
	}

	// Step 5: Output = [original message blocks | encrypted permuted parity blocks].
	result := make([][]byte, m+totalParity)
	copy(result[:m], blocks)
	copy(result[m:], encParity)
	return result, nil
}

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

// Params holds the public system parameters for the POR scheme.
// All fields except GSeed are chosen before key generation; GSeed is set by KeyGen.
type Params struct {
	// V is the inner code message length: number of file blocks sampled per
	// challenge. Higher V gives better error tolerance but more server I/O.
	// §4.2.1: "v pseudorandom block indices i_1,...,i_v ∈ [1,t]".
	V int

	// W is the inner code codeword length (nonce domain size). The minimum
	// distance of ECCin is d_1 = W-V+1 (§4.2.2, Theorem 2 condition ε ≤ d_1/(2W)).
	W int

	// Q is the number of precomputed challenge-response pairs (sentinels).
	// Supports at most Q phase-one verifications. §4.2.1: "q challenges".
	Q int

	// P is the prime field modulus for inner code arithmetic over Z_P.
	// P > SHA256(any block), so a 256-bit prime suffices.
	P *big.Int

	// GSeed is the public seed for deriving G[s][u] = PRF(PRF(GSeed,u), s) mod P.
	// Set by KeyGen and shared with the server so it can reconstruct G without
	// any client secrets.
	GSeed []byte

	// OuterN and OuterK are the RS outer code parameters per stripe:
	// OuterN total symbols, OuterK message symbols, d_2 = OuterN-OuterK+1.
	// §4.2: "(n,k,d) Reed-Solomon code ECCout" with d_2 ≥ 2 for correction.
	OuterN int
	OuterK int
}

// MasterKey holds the master secret key and all derived sub-keys.
// Only the client holds MasterKey; it is never transmitted to the server.
// §4.2.1: "a master secret key MS is generated, from which additional keys
// are derived: KChal, KInd, KMACFile, KEnc, KPerm, KECCPerm, KECCEnc".
type MasterKey struct {
	KChal    []byte // challenge key: k_j^c = HMAC(KChal, j)
	KInd     []byte // index key: u_j = PRF(KInd, j) mod W
	KMACFile []byte // file MAC key: HMAC over all encoded blocks and sentinels
	KEnc     []byte // encryption key: k_j^e = HMAC(KEnc, j)
	KPerm    []byte // file permutation key: PRP for SA-ECC stripe assignment
	KECCPerm []byte // parity permutation key: PRP for SA-ECC parity ordering
	KECCEnc  []byte // parity encryption key: AES-CTR for individual parity blocks
	Params   *Params
}

// EncodedFile is the output of Encode, stored on the server.
// The client retains only MasterKey.
type EncodedFile struct {
	// Blocks = [original file blocks | permuted encrypted parity blocks].
	// Blocks[0:NumMessage] are the original file blocks (systematic outer code).
	Blocks     [][]byte
	NumMessage int

	// Sentinels[j-1] = Q_j = GCM-Enc(k_j^e, M_j), the encrypted precomputed
	// inner code response for challenge j (1-indexed).
	// §4.2.1: "Q_j = Enc(k_j^e, M_j)" appended to the encoded file.
	Sentinels [][]byte

	// FileMAC = HMAC-SHA256(KMACFile, all blocks ‖ all sentinels).
	FileMAC []byte

	// Params holds the system parameters needed by Respond; shared with server.
	Params *Params
}

// Challenge is sent from the client to the server.
// §4.2.1 challenge: "the client sends to the server j, k_j^c and the random index u".
type Challenge struct {
	J   int    // sentinel index ∈ [1, Q]
	Kjc []byte // per-challenge PRF key for deriving block indices i_1,...,i_v
	U   int    // inner code column index ∈ [1, W]
}

// Response is returned by the server to a Challenge.
// §4.2.1 respond: "the server computes M_j and returns M_j and Q_j".
type Response struct {
	// Mj = Σ_{s=1}^v SHA256(F̃_{i_s}) · G[s][U] mod P,
	// encoded as a fixed-length big-endian integer of length (P.BitLen()+7)/8.
	Mj []byte
	// Qj is the sentinel ciphertext retrieved from EncodedFile.Sentinels[J-1].
	Qj []byte
}

// ---------------------------------------------------------------------------
// Protocol functions
// ---------------------------------------------------------------------------

// KeyGen generates a fresh MasterKey for the POR scheme.
//
// params must be fully populated except params.GSeed, which is generated here.
// Use mk.Params (not the original params pointer) for all subsequent calls.
//
// §4.2.1 keygen: "generates a master secret key MS from which additional keys
// are derived".
func KeyGen(params *Params) (*MasterKey, error) {
	ms := make([]byte, 32)
	if _, err := rand.Read(ms); err != nil {
		return nil, fmt.Errorf("por.KeyGen: %w", err)
	}

	gseed := make([]byte, 32)
	if _, err := rand.Read(gseed); err != nil {
		return nil, fmt.Errorf("por.KeyGen: reading GSeed: %w", err)
	}

	p := *params
	p.GSeed = gseed

	return &MasterKey{
		KChal:    deriveKey(ms, "kchal"),
		KInd:     deriveKey(ms, "kind"),
		KMACFile: deriveKey(ms, "kmacfile"),
		KEnc:     deriveKey(ms, "kenc"),
		KPerm:    deriveKey(ms, "kperm"),
		KECCPerm: deriveKey(ms, "keccperm"),
		KECCEnc:  deriveKey(ms, "keccenc"),
		Params:   &p,
	}, nil
}

// Encode applies SA-ECC to file F and precomputes Q sentinel values.
// The returned EncodedFile is uploaded to the server; the client discards it
// and retains only mk.
//
// §4.2.1 encode: applies SA-ECC, precomputes Q_j = Enc(k_j^e, M_j) for each
// j ∈ [1,Q], and appends MAC_KMACFile(F̃).
func Encode(mk *MasterKey, file [][]byte) (*EncodedFile, error) {
	p := mk.Params

	encoded, err := saeccEncode(file, p.OuterN, p.OuterK, mk.KPerm, mk.KECCPerm, mk.KECCEnc)
	if err != nil {
		return nil, fmt.Errorf("por.Encode: %w", err)
	}
	t := len(encoded)

	sentinels := make([][]byte, p.Q)
	for j := 1; j <= p.Q; j++ {
		kjc := challengeKey(mk.KChal, j)
		u := deriveU(mk.KInd, j, p.W)
		indices := blockIndices(kjc, p.V, t)

		M := computeInnerResponse(encoded, indices, p.GSeed, u, p.P)
		Q, err := sentinelEncrypt(encryptionKey(mk.KEnc, j), mToBytes(M, p.P))
		if err != nil {
			return nil, fmt.Errorf("por.Encode: sentinel %d: %w", j, err)
		}
		sentinels[j-1] = Q
	}

	mac := hmac.New(sha256.New, mk.KMACFile)
	for _, b := range encoded {
		mac.Write(b)
	}
	for _, s := range sentinels {
		mac.Write(s)
	}

	return &EncodedFile{
		Blocks:     encoded,
		NumMessage: len(file),
		Sentinels:  sentinels,
		FileMAC:    mac.Sum(nil),
		Params:     p,
	}, nil
}

// MakeChallenge generates challenge c for sentinel index j ∈ [1, Q].
// The client keeps mk and sends c to the server.
//
// §4.2.1 challenge: derives k_j^c = HMAC(KChal, j) and u = PRF(KInd, j) mod W.
func MakeChallenge(mk *MasterKey, j int) (*Challenge, error) {
	if j < 1 || j > mk.Params.Q {
		return nil, fmt.Errorf("por.MakeChallenge: j=%d out of range [1, %d]", j, mk.Params.Q)
	}
	return &Challenge{
		J:   j,
		Kjc: challengeKey(mk.KChal, j),
		U:   deriveU(mk.KInd, j, mk.Params.W),
	}, nil
}

// Respond is run by the server to answer a challenge.
//
// It uses chal.Kjc to derive v block indices (via pdp.SuiteV1.BuildPRP),
// reads those blocks from ef.Blocks, and computes the inner code linear
// combination M_j = Σ SHA256(block_{i_s}) · G[s][u] mod P. It also retrieves
// the stored sentinel Q_j from ef.Sentinels[j-1].
//
// §4.2.1 respond: "the server derives i_1,...,i_v from k_j^c, computes M_j,
// and returns M_j and Q_j".
func Respond(ef *EncodedFile, chal *Challenge) (*Response, error) {
	p := ef.Params
	if chal.J < 1 || chal.J > p.Q {
		return nil, fmt.Errorf("por.Respond: j=%d out of range [1, %d]", chal.J, p.Q)
	}
	if chal.U < 1 || chal.U > p.W {
		return nil, fmt.Errorf("por.Respond: u=%d out of range [1, %d]", chal.U, p.W)
	}

	indices := blockIndices(chal.Kjc, p.V, len(ef.Blocks))
	M := computeInnerResponse(ef.Blocks, indices, p.GSeed, chal.U, p.P)

	return &Response{
		Mj: mToBytes(M, p.P),
		Qj: ef.Sentinels[chal.J-1],
	}, nil
}

// Verify checks whether the server's response to challenge c is correct.
//
// It decrypts Q_j with k_j^e = HMAC(KEnc, j) and compares the result to M_j.
// If decryption fails (GCM authentication tag mismatch), the sentinel is
// corrupted and Verify returns (false, nil).
//
// §4.2.1 verify: "returns true if M_j == Dec(k_j^e, Q_j)".
func Verify(mk *MasterKey, chal *Challenge, resp *Response) (bool, error) {
	if chal.J < 1 || chal.J > mk.Params.Q {
		return false, fmt.Errorf("por.Verify: j=%d out of range [1, %d]", chal.J, mk.Params.Q)
	}

	kje := encryptionKey(mk.KEnc, chal.J)
	decrypted, err := sentinelDecrypt(kje, resp.Qj)
	if err != nil {
		// GCM authentication failure: sentinel corrupted or forged.
		return false, nil
	}
	return bytes.Equal(decrypted, resp.Mj), nil
}
