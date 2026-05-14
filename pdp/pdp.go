// Package pdp defines the PublicKey type shared by the Ateniese (static) and
// Erway (dynamic) PDP schemes, and provides the RSA group-setup primitives both
// schemes use for key generation.
//
// Callers who want to run a complete PDP protocol should import one of the
// sub-packages:
//
//	pdp/ateniese — S-PDP (Ateniese et al., CCS 2007), static, unlimited challenges
//	pdp/erway    — DPDP I (Erway et al., CCS 2009), dynamic (insert/modify/delete)
//
// Cryptographic suite selection (PRF, PRP, hash primitives) is handled by the
// suite package; import github.com/pinionengineering/storage-proofs/suite for
// suite.SuiteV1 and friends.
package pdp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// PublicKey holds the RSA group parameters shared by both PDP schemes.
//
//   - N is the RSA modulus N = p*q, where p and q are safe primes.
//   - G is a generator of QR_N, the cyclic group of quadratic residues mod N,
//     with order phi = p'*q' (where p = 2p'+1, q = 2q'+1).
type PublicKey struct {
	N *big.Int
	G *big.Int
}

// MakePublicKey generates a fresh RSA group over safe primes.
// k is the security parameter in bits for each prime; N is approximately 2k bits.
// Both the Ateniese and Erway schemes call this from their own KeyGen functions.
func MakePublicKey(k int) (*PublicKey, error) {
	p, _, err := GenerateSafePrime(k)
	if err != nil {
		return nil, fmt.Errorf("pdp.MakePublicKey: p: %w", err)
	}
	q, _, err := GenerateSafePrime(k)
	if err != nil {
		return nil, fmt.Errorf("pdp.MakePublicKey: q: %w", err)
	}
	N := new(big.Int).Mul(p, q)
	G, err := GenerateGQRN(N)
	if err != nil {
		return nil, fmt.Errorf("pdp.MakePublicKey: G: %w", err)
	}
	return &PublicKey{N: N, G: G}, nil
}

// GenerateSafePrime returns a safe prime p = 2*p' + 1 of the requested bit
// length, along with the Sophie Germain prime p'. Both sub-packages use this
// to build N.
func GenerateSafePrime(bits int) (p, pPrime *big.Int, err error) {
	one := big.NewInt(1)
	for {
		pPrime, err = rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, nil, err
		}
		p = new(big.Int).Lsh(pPrime, 1)
		p.Add(p, one)
		if p.ProbablyPrime(20) {
			return p, pPrime, nil
		}
	}
}

// GenerateGQRN returns a generator g of QR_N — the cyclic subgroup of quadratic
// residues mod N of order p'*q'. Per §4.3 of the Ateniese paper: choose
// a ← Z*_N with gcd(a±1, N) = 1, then set g = a² mod N.
func GenerateGQRN(N *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	nMinus1 := new(big.Int).Sub(N, one)
	for {
		a, err := rand.Int(rand.Reader, nMinus1)
		if err != nil {
			return nil, err
		}
		a.Add(a, one)
		if new(big.Int).GCD(nil, nil, a, N).Cmp(one) != 0 {
			continue
		}
		aMinus1 := new(big.Int).Sub(a, one)
		if new(big.Int).GCD(nil, nil, aMinus1, N).Cmp(one) != 0 {
			continue
		}
		aPlus1 := new(big.Int).Add(a, one)
		if new(big.Int).GCD(nil, nil, aPlus1, N).Cmp(one) != 0 {
			continue
		}
		return new(big.Int).Exp(a, two, N), nil
	}
}

