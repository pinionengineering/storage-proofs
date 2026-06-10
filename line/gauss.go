package line

import "math/big"

// GaussElimModP solves an N-unknown linear system over Z_P given an augmented
// matrix aug with M rows and N+1 columns (column N is the RHS). Performs full
// reduced row echelon elimination. Returns the solution vector of length N, or
// nil if the system is rank-deficient (call site should return ErrInsufficientProofs).
//
// In POR extraction, each witnessed proof contributes one row: the coefficients
// are the challenge weights applied to each block, and the RHS is the linear
// combination of block values the prover returned. Once enough proofs have been
// witnessed the system becomes full-rank and can be solved for the individual
// block values.
func GaussElimModP(aug [][]*big.Int, N int, P *big.Int) []*big.Int {
	M := len(aug)

	// Deep copy so the caller's slice is not mutated.
	a := make([][]*big.Int, M)
	for i, row := range aug {
		a[i] = make([]*big.Int, N+1)
		for j := range a[i] {
			if j < len(row) && row[j] != nil {
				a[i][j] = new(big.Int).Set(row[j])
			} else {
				a[i][j] = new(big.Int)
			}
		}
	}

	pivotRow := 0
	pivotAt := make([]int, N) // pivotAt[c] = row whose pivot is column c, or -1
	for c := range N {
		pivotAt[c] = -1
	}

	for c := 0; c < N && pivotRow < M; c++ {
		// Find a non-zero entry in column c at or below pivotRow.
		found := -1
		for r := pivotRow; r < M; r++ {
			if a[r][c].Sign() != 0 {
				found = r
				break
			}
		}
		if found == -1 {
			continue // column c is a free variable
		}

		a[pivotRow], a[found] = a[found], a[pivotRow]

		// Scale the pivot row so a[pivotRow][c] == 1.
		inv := new(big.Int).ModInverse(a[pivotRow][c], P)
		for j := c; j <= N; j++ {
			a[pivotRow][j].Mul(a[pivotRow][j], inv)
			a[pivotRow][j].Mod(a[pivotRow][j], P)
		}

		// Eliminate column c from every other row.
		for r := 0; r < M; r++ {
			if r == pivotRow || a[r][c].Sign() == 0 {
				continue
			}
			factor := new(big.Int).Set(a[r][c])
			for j := c; j <= N; j++ {
				a[r][j].Sub(a[r][j], new(big.Int).Mul(factor, a[pivotRow][j]))
				a[r][j].Mod(a[r][j], P)
			}
		}

		pivotAt[c] = pivotRow
		pivotRow++
	}

	// Rank-deficiency check: every column must have a pivot.
	for c := range N {
		if pivotAt[c] == -1 {
			return nil
		}
	}

	sol := make([]*big.Int, N)
	for c := range N {
		sol[c] = new(big.Int).Set(a[pivotAt[c]][N])
	}
	return sol
}
