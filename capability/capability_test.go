package capability

import "testing"

// TestSwPSectorBytesFit guards exactly the class of bug that motivated this
// package's SW-Priv/SW-Pub constants: swP must stay big enough for
// swSectorBytes regardless of any future change to either constant.
func TestSwPSectorBytesFit(t *testing.T) {
	if swP.BitLen() <= 8*swSectorBytes {
		t.Fatalf("swP.BitLen()=%d must be > 8*swSectorBytes=%d", swP.BitLen(), 8*swSectorBytes)
	}
}
