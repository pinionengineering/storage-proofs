package confidence

import (
	"math"
	"testing"
)

func TestHypergeometricDetection(t *testing.T) {
	tests := []struct {
		n, c        int
		corrupt     float64
		wantAtLeast float64 // lower bound
		wantAtMost  float64 // upper bound
	}{
		// No corruption → no detection.
		{n: 1000, c: 10, corrupt: 0, wantAtLeast: 0, wantAtMost: 0},
		// All blocks corrupted → certain detection.
		{n: 1000, c: 10, corrupt: 1.0, wantAtLeast: 1, wantAtMost: 1},
		// 1% corrupt, 460 challenged out of 10000 → ~99% detection.
		{n: 10000, c: 460, corrupt: 0.01, wantAtLeast: 0.99, wantAtMost: 1.0},
		// 50% corrupt, 10 challenged → high detection.
		{n: 1000, c: 10, corrupt: 0.5, wantAtLeast: 0.999, wantAtMost: 1.0},
		// Small case: 3 blocks, 1 corrupted, challenge 1 → P = 1/3.
		{n: 3, c: 1, corrupt: 1.0 / 3.0, wantAtLeast: 0.333, wantAtMost: 0.334},
	}

	for _, tt := range tests {
		got := HypergeometricDetection(tt.n, tt.c, tt.corrupt)
		if got < tt.wantAtLeast || got > tt.wantAtMost {
			t.Errorf("HypergeometricDetection(%d, %d, %g) = %g, want [%g, %g]",
				tt.n, tt.c, tt.corrupt, got, tt.wantAtLeast, tt.wantAtMost)
		}
	}
}

func TestCumulativeDetection(t *testing.T) {
	// Zero rounds → zero probability.
	if got := CumulativeDetection(0.5, 0); got != 0 {
		t.Errorf("got %g, want 0", got)
	}
	// Certain per-round → certain cumulative.
	if got := CumulativeDetection(1.0, 5); got != 1 {
		t.Errorf("got %g, want 1", got)
	}
	// 10% per round, 22 rounds → ~90% cumulative (1 - 0.9^22 ≈ 0.9).
	got := CumulativeDetection(0.1, 22)
	if math.Abs(got-0.9) > 0.01 {
		t.Errorf("got %g, want ~0.9", got)
	}
}
