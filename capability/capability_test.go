package capability

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// TestSwPForSectorBytesFit guards that swPForSectorBytes always returns a P
// big enough for the requested sector size, for every size SW-Priv might use.
func TestSwPForSectorBytesFit(t *testing.T) {
	for _, sectorBytes := range []int{1, 16, 31, 64, 128} {
		p, err := swPForSectorBytes(sectorBytes)
		if err != nil {
			t.Fatalf("swPForSectorBytes(%d): %v", sectorBytes, err)
		}
		if p.BitLen() <= 8*sectorBytes {
			t.Fatalf("swPForSectorBytes(%d).BitLen()=%d must be > %d", sectorBytes, p.BitLen(), 8*sectorBytes)
		}
	}
}

// TestMaxSWPubSectorBytesFit guards exactly the class of bug that motivated
// this constant: every possible MaxSWPubSectorBytes-byte value must be
// strictly less than BN254's scalar field order, and MaxSWPubSectorBytes+1
// bytes must not be, so the boundary can never silently drift.
func TestMaxSWPubSectorBytesFit(t *testing.T) {
	order := fr.Modulus()

	maxSafe := new(big.Int).Lsh(big.NewInt(1), uint(8*MaxSWPubSectorBytes))
	if maxSafe.Cmp(order) > 0 {
		t.Fatalf("2^(8*%d)=%s exceeds BN254 order %s", MaxSWPubSectorBytes, maxSafe, order)
	}

	oneMore := new(big.Int).Lsh(big.NewInt(1), uint(8*(MaxSWPubSectorBytes+1)))
	if oneMore.Cmp(order) <= 0 {
		t.Fatalf("2^(8*%d)=%s does not exceed BN254 order %s; MaxSWPubSectorBytes could be larger", MaxSWPubSectorBytes+1, oneMore, order)
	}
}
