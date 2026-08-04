// File-tag wrapping for the §3.2 private-key scheme (Shacham-Waters,
// "Compact Proofs of Retrievability", ASIACRYPT 2008).
//
// §3.2's own Priv.Kg/Priv.St/Priv.V split is more than "generate (K, Alpha),
// keep it forever": the client's only long-term secret is meant to be a
// small, reusable key sk = (k_enc, k_mac) (Priv.Kg). Each file gets its own
// fresh (k_prf, α_1..α_S), generated at tagging time (Priv.St), encrypted
// and MAC'd into a "file tag" t = t0 || MAC_kmac(t0), where
// t0 = n || Enc_kenc(kprf||α_1||...||α_S), and stored alongside the file
// with the (untrusted) server. At audit time the verifier fetches t back,
// recovers (k_prf, α) under its one reusable key (Priv.V), and only then
// runs the challenge/verify KeyGen/TagBlocks/Verify already implement.
//
// This file adds that mechanism on top of the existing per-file primitives
// without changing them: WrapKey is the reusable §3.2 Priv.Kg secret,
// SealFileTag is Priv.St's wrapping step, and OpenFileTag is Priv.V's
// unwrapping step. A caller that only ever tags one file under one key can
// ignore this file entirely and keep using KeyGen/TagBlocks/Verify directly,
// exactly as before.
//
// # Deviations from the paper
//
// AEAD instead of generic Enc+MAC: §3.2 leaves both primitives unspecified.
// This implementation uses one AES-256-GCM key for both roles rather than
// separate encrypt and MAC primitives. GCM's Open call authenticates before
// ever returning plaintext, which collapses Priv.V's separate "verify the
// MAC, then decrypt" into one atomic step with no window where an
// unauthenticated plaintext exists.
//
// ids-digest binding: the paper's own Priv.St is called once per file, with
// no other file sharing its wrapping key in mind, so it has no cross-file
// threat to defend against. That changes the moment one WrapKey spans many
// files, which is this mechanism's whole point: without a binding, a
// dishonest storage provider holding several FileTags sealed under the same
// WrapKey could swap two files' tags, and OpenFileTag would decrypt
// successfully either way, silently pairing the wrong (k_prf, α) with a
// given file's blocks. SealFileTag/OpenFileTag close this by using a digest
// of the file's own ids (block identifiers) as the AEAD's associated data,
// the same principle pdp/ateniese's CheckProof and this package's own
// Verify already rely on: derive the binding from the verifier's own
// trusted state, never trust it from something the untrusted party hands
// back. This also subsumes the paper's own inclusion of n (block count) in
// t0, since the digest is a function of the exact id set, which determines
// n implicitly.
package sw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// WrapKey is §3.2 Priv.Kg's reusable client secret sk=(k_enc,k_mac),
// generalized to a single AES-256-GCM key (see package doc's "Deviations
// from the paper"). Unlike SecretKey, which KeyGen generates fresh per file
// (Priv.St), a WrapKey is meant to be generated once and reused across many
// files that share the same audit relationship, e.g. one per untrusted
// storage provider.
type WrapKey struct {
	// Key is the AES-256-GCM key, 32 bytes.
	Key    []byte
	Params *Params
}

// WrapKeyGen generates a fresh WrapKey (§3.2 Priv.Kg). params is shared by
// every file later sealed under this key, the same way sw-pub's PubScheme
// holds its sector count once for every root tagged under it rather than
// re-specifying it per root.
func WrapKeyGen(params *Params) (*WrapKey, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("sw.WrapKeyGen: %w", err)
	}
	return &WrapKey{Key: key, Params: params}, nil
}

// FileTag is §3.2's t = t0 || MAC_kmac(t0), t0 = n || Enc_kenc(kprf||
// α_1||...||α_S): the encrypted, authenticated per-file secret. Meant to be
// stored alongside the file with the untrusted server and fetched back by
// the verifier at audit time; see OpenFileTag.
type FileTag struct {
	Nonce      []byte
	Ciphertext []byte
}

// idsDigest computes a SHA-256 digest over ids, each length-prefixed before
// hashing, giving a fixed-size binding to the exact set and order of block
// identifiers a FileTag was sealed for. Length-prefixing prevents
// concatenation ambiguity between two different id lists (e.g. ["ab","c"]
// and ["a","bc"] must never collide).
func idsDigest(ids [][]byte) []byte {
	h := sha256.New()
	var lenBuf [4]byte
	for _, id := range ids {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(id)))
		h.Write(lenBuf[:])
		h.Write(id)
	}
	return h.Sum(nil)
}

// encodeSecret serializes (K, Alpha) as the AEAD plaintext: a 4-byte length
// prefix before each field prevents ambiguity between K and the Alpha
// values it precedes.
func encodeSecret(sk *SecretKey) []byte {
	var out []byte
	out = appendLenPrefixed(out, sk.K)
	for _, a := range sk.Alpha {
		out = appendLenPrefixed(out, a.Bytes())
	}
	return out
}

func appendLenPrefixed(dst, part []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(part)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, part...)
	return dst
}

// decodeSecret is encodeSecret's inverse. wantAlpha is the expected number
// of Alpha entries (from WrapKey.Params.S), checked so a plaintext with the
// wrong shape (e.g. from a WrapKey whose Params.S doesn't match what this
// file was actually sealed with) is rejected explicitly rather than
// silently truncated or padded.
func decodeSecret(plaintext []byte, wantAlpha int) (k []byte, alpha []*big.Int, err error) {
	read := func() ([]byte, error) {
		if len(plaintext) < 4 {
			return nil, fmt.Errorf("sw: truncated file tag plaintext")
		}
		n := binary.BigEndian.Uint32(plaintext[:4])
		plaintext = plaintext[4:]
		if uint64(len(plaintext)) < uint64(n) {
			return nil, fmt.Errorf("sw: truncated file tag plaintext")
		}
		field := plaintext[:n]
		plaintext = plaintext[n:]
		return field, nil
	}

	k, err = read()
	if err != nil {
		return nil, nil, err
	}
	alpha = make([]*big.Int, wantAlpha)
	for j := range wantAlpha {
		b, err := read()
		if err != nil {
			return nil, nil, err
		}
		alpha[j] = new(big.Int).SetBytes(b)
	}
	if len(plaintext) != 0 {
		return nil, nil, fmt.Errorf("sw: file tag plaintext has %d trailing bytes", len(plaintext))
	}
	return k, alpha, nil
}

// SealFileTag generates a fresh per-file SecretKey (§3.2 Priv.St: "choose a
// PRF key kprf and s random numbers α_1,...,α_S") and seals it into a
// FileTag under wrapKey, authenticated against ids (see package doc's
// "Deviations from the paper" for why). Returns the SecretKey too, ready to
// pass directly to the existing TagBlocks.
func SealFileTag(wrapKey *WrapKey, ids [][]byte) (*SecretKey, *FileTag, error) {
	sk, err := KeyGen(wrapKey.Params)
	if err != nil {
		return nil, nil, fmt.Errorf("sw.SealFileTag: %w", err)
	}

	block, err := aes.NewCipher(wrapKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sw.SealFileTag: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("sw.SealFileTag: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("sw.SealFileTag: %w", err)
	}

	plaintext := encodeSecret(sk)
	ciphertext := gcm.Seal(nil, nonce, plaintext, idsDigest(ids))

	return sk, &FileTag{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// OpenFileTag recovers the SecretKey sealed in tag (§3.2 Priv.V: "use kenc
// to decrypt the encrypted portions, recovering... kprf and α"), verifying
// it was created for exactly this ids set. Returns an error on any
// mismatch: wrong wrapKey, a tampered tag, or ids belonging to a different
// file than the one tag was sealed for.
func OpenFileTag(wrapKey *WrapKey, tag *FileTag, ids [][]byte) (*SecretKey, error) {
	block, err := aes.NewCipher(wrapKey.Key)
	if err != nil {
		return nil, fmt.Errorf("sw.OpenFileTag: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sw.OpenFileTag: %w", err)
	}

	plaintext, err := gcm.Open(nil, tag.Nonce, tag.Ciphertext, idsDigest(ids))
	if err != nil {
		return nil, fmt.Errorf("sw.OpenFileTag: authentication failed: %w", err)
	}

	k, alpha, err := decodeSecret(plaintext, wrapKey.Params.S)
	if err != nil {
		return nil, fmt.Errorf("sw.OpenFileTag: %w", err)
	}

	return &SecretKey{K: k, Alpha: alpha, Params: wrapKey.Params}, nil
}
