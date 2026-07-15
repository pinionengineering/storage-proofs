package main

import (
	"errors"
	"fmt"
	"sync"

	blockspkg "github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/capability"
	"github.com/pinionengineering/storage-proofs/line"
)

// rec is one cell of the experiment matrix.
type rec struct {
	sch schemeSpec
	n   int
	c   int
	m   Metrics
}

// measuredSeries pairs each scheme's measured points with a scaled theory curve.
func measuredSeries(pts map[string][]Point, theoryFn func(name string, x float64) float64) []Series {
	var out []Series
	for _, sch := range schemes {
		out = append(out, Series{Label: sch.Name, Color: sch.color, Points: pts[sch.Name]})
		theory := scaleTheory(pts[sch.Name], func(x float64) float64 { return theoryFn(sch.Name, x) })
		out = append(out, Series{Label: sch.Name + " (theory)", Color: sch.color, Dash: true, Points: theory})
	}
	return out
}

// wireTheory builds series using absolute (not scaled) formula values.
func wireTheory(pts map[string][]Point, formula func(string, int) int) []Series {
	var out []Series
	for _, sch := range schemes {
		out = append(out, Series{Label: sch.Name, Color: sch.color, Points: pts[sch.Name]})
		theory := make([]Point, len(pts[sch.Name]))
		for i, p := range pts[sch.Name] {
			theory[i] = Point{p.X, float64(formula(sch.Name, int(p.X)))}
		}
		out = append(out, Series{Label: sch.Name + " (theory)", Color: sch.color, Dash: true, Points: theory})
	}
	return out
}

// project reduces the matrix to a set of points along one axis.
func project(data []rec, keep func(rec) bool, x, y func(rec) float64) map[string][]Point {
	pts := map[string][]Point{}
	for _, r := range data {
		if keep(r) {
			pts[r.sch.Name] = append(pts[r.sch.Name], Point{x(r), y(r)})
		}
	}
	return pts
}

func runSweep() (*Charts, error) {
	// -----------------------------------------------------------------------
	// Matrix: all (n × c × scheme) combinations at fixedKeyBits, in parallel.
	// -----------------------------------------------------------------------
	fmt.Println("matrix sweep (n × c × scheme)...")

	stores := make(map[int]blockspkg.BlockStore, len(fileSweepN))
	for _, n := range fileSweepN {
		stores[n] = blockspkg.NewMemStore(randomBlocks(n))
	}

	type matCell struct {
		sch   schemeSpec
		store blockspkg.BlockStore
		n, c  int
	}
	cells := make([]matCell, 0, len(fileSweepN)*len(chalSweepC)*len(schemes))
	for _, n := range fileSweepN {
		for _, c := range chalSweepC {
			for _, sch := range schemes {
				cells = append(cells, matCell{sch, stores[n], n, c})
			}
		}
	}

	type matResult struct {
		r   rec
		err error
	}
	matResults := make([]matResult, len(cells))
	var wg sync.WaitGroup
	for i, cl := range cells {
		wg.Add(1)
		go func(i int, cl matCell) {
			defer wg.Done()
			m, err := run(cl.sch, cl.store, Params{
				KeyBits: fixedKeyBits, NBlocks: cl.n, ChalSize: cl.c,
				BlockSize: fixedBlockSz, SectorsPerBlock: fixedSectorsPerBlock,
			})
			matResults[i] = matResult{rec{cl.sch, cl.n, cl.c, m}, err}
		}(i, cl)
	}
	wg.Wait()

	var data []rec
	for _, r := range matResults {
		if r.err != nil {
			return nil, r.err
		}
		data = append(data, r.r)
	}

	// Project the matrix onto chart axes by slicing at the fixed coordinate.
	byN := func(metric func(Metrics) float64) map[string][]Point {
		return project(data,
			func(r rec) bool { return r.c == fixedChalSize },
			func(r rec) float64 { return float64(r.n) },
			func(r rec) float64 { return metric(r.m) },
		)
	}
	byC := func(metric func(Metrics) float64) map[string][]Point {
		return project(data,
			func(r rec) bool { return r.n == fixedNBlocks },
			func(r rec) float64 { return float64(r.c) },
			func(r rec) float64 { return metric(r.m) },
		)
	}

	tagChart := LineChart{
		XLabel: "Blocks (N)", YLabel: "Setup time (µs)",
		Series: measuredSeries(byN(func(m Metrics) float64 { return float64(m.SetupTime) }),
			func(s string, x float64) float64 { return tagTimeScale(s, int(x)) }),
	}
	proveChart := LineChart{
		XLabel: "Challenge size (C)", YLabel: "Prove time (µs)",
		Series: measuredSeries(byC(func(m Metrics) float64 { return float64(m.ProveTime) }),
			func(s string, x float64) float64 { return proveTimeScale(s, int(x), fixedNBlocks) }),
	}
	verifyChart := LineChart{
		XLabel: "Challenge size (C)", YLabel: "Verify time (µs)",
		Series: measuredSeries(byC(func(m Metrics) float64 { return float64(m.VerifyTime) }),
			func(s string, x float64) float64 { return verifyTimeScale(s, int(x), fixedNBlocks) }),
	}
	chalChart := LineChart{
		XLabel: "Challenge size (C)", YLabel: "Challenge bytes",
		Series: wireTheory(byC(func(m Metrics) float64 { return float64(m.ChalLen) }),
			func(s string, c int) int { return challengeBytesFormula(s, c, fixedKeyBits, swPLen) }),
	}
	proofChart := LineChart{
		XLabel: "Challenge size (C)", YLabel: "Proof bytes",
		Series: wireTheory(byC(func(m Metrics) float64 { return float64(m.ProofLen) }),
			func(s string, c int) int { return proofBytesFormula(s, c, fixedKeyBits, fixedNBlocks, swPLen, swS, bjoPLen) }),
	}

	// Suite comparison: the (fixedNBlocks, fixedChalSize) point from the matrix.
	names := make([]string, len(schemes))
	setupV, proveV, verifyV := make([]float64, len(schemes)), make([]float64, len(schemes)), make([]float64, len(schemes))
	for i, sch := range schemes {
		names[i] = sch.Name
		for _, r := range data {
			if r.sch.Name == sch.Name && r.n == fixedNBlocks && r.c == fixedChalSize {
				setupV[i], proveV[i], verifyV[i] = float64(r.m.SetupTime), float64(r.m.ProveTime), float64(r.m.VerifyTime)
			}
		}
	}
	suiteSweep := SuiteSweepData{
		Schemes: names,
		Setup:   []BarGroup{{Label: "Setup", Color: "#64748b", Values: setupV}},
		Prove:   []BarGroup{{Label: "Prove", Color: "#3b82f6", Values: proveV}},
		Verify:  []BarGroup{{Label: "Verify", Color: "#10b981", Values: verifyV}},
	}

	// -----------------------------------------------------------------------
	// Key size sweep: varies keyBits for RSA-based schemes (Ateniese, Erway),
	// in parallel.
	// -----------------------------------------------------------------------
	fmt.Println("key size sweep...")
	keyStore := blockspkg.NewMemStore(randomBlocks(fixedNBlocks))

	keyGrid := make([][]Metrics, len(keySweepBits))
	keyErrs := make([][]error, len(keySweepBits))
	for i := range keyGrid {
		keyGrid[i] = make([]Metrics, 2)
		keyErrs[i] = make([]error, 2)
	}
	for i, kb := range keySweepBits {
		for j, sch := range schemes[:2] { // Ateniese, Erway
			wg.Add(1)
			go func(i, j int, sch schemeSpec, kb int) {
				defer wg.Done()
				m, err := run(sch, keyStore, Params{KeyBits: kb, NBlocks: fixedNBlocks, ChalSize: fixedChalSize})
				keyGrid[i][j], keyErrs[i][j] = m, err
			}(i, j, sch, kb)
		}
	}
	wg.Wait()

	keyPts := map[string][]Point{}
	for i, kb := range keySweepBits {
		for j, sch := range schemes[:2] {
			if keyErrs[i][j] != nil {
				return nil, keyErrs[i][j]
			}
			keyPts[sch.Name] = append(keyPts[sch.Name], Point{float64(kb), float64(keyGrid[i][j].SetupTime)})
		}
	}
	var keySeries []Series
	for _, sch := range schemes[:2] {
		keySeries = append(keySeries, Series{Label: sch.Name, Color: sch.color, Points: keyPts[sch.Name]})
		theory := scaleTheory(keyPts[sch.Name], func(x float64) float64 { return keyTimeScale(sch.Name, int(x)) })
		keySeries = append(keySeries, Series{Label: sch.Name + " (theory)", Color: sch.color, Dash: true, Points: theory})
	}
	keyChart := LineChart{XLabel: "Key bits", YLabel: "Setup time (µs)", Series: keySeries}

	// -----------------------------------------------------------------------
	// Detection sweep: Monte Carlo over corruption fractions.
	// Separate because it varies the store contents per trial, not per run.
	// -----------------------------------------------------------------------
	fmt.Println("detection sweep...")
	detChart, err := sweepDetection()
	if err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------------
	// Extraction sweep: count witnesses needed to recover the file passively.
	// Only SW-Priv and BJO support extraction.
	// -----------------------------------------------------------------------
	fmt.Println("extraction sweep...")
	extractChart, err := sweepExtraction()
	if err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------------
	// GB projection: real (not extrapolated) tag/prove time at gbProjectionBytes.
	// -----------------------------------------------------------------------
	fmt.Println("gb projection...")
	gbChart, err := benchGBProjection()
	if err != nil {
		return nil, err
	}

	return &Charts{
		TagTime:      tagChart,
		ProveTime:    proveChart,
		VerifyTime:   verifyChart,
		ChalBytes:    chalChart,
		ProofBytes:   proofChart,
		KeySweep:     keyChart,
		Detection:    detChart,
		Extraction:   extractChart,
		SuiteSweep:   suiteSweep,
		GBProjection: gbChart,
	}, nil
}

// benchGBProjection measures real tag and prove CPU time for a
// gbProjectionBytes-sized store, using one common block size for every
// scheme (capability.MaxSWPubSectorBytes * fixedSectorsPerBlock — SW-Pub's best
// case, applied uniformly so all schemes are compared on equal footing).
// Unlike the rest of this sweep, this runs the real operation at the real
// target size rather than fitting/extrapolating from smaller N — some
// schemes take genuinely long at this scale, which is the point of this
// chart.
func benchGBProjection() (GBProjectionData, error) {
	blockSize := capability.MaxSWPubSectorBytes * fixedSectorsPerBlock
	n := gbProjectionBytes / blockSize

	names := make([]string, len(schemes))
	tagV := make([]float64, len(schemes))
	proveV := make([]float64, len(schemes))

	for i, sch := range schemes {
		fmt.Printf("  gb %s: n=%d blocks of %d bytes\n", sch.Name, n, blockSize)
		names[i] = sch.Name
		store := blockspkg.NewMemStore(randomBlocksOfSize(n, blockSize))

		tagger, err := sch.NewTagger(fixedKeyBits, fixedChalSize, blockSize, fixedSectorsPerBlock)
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb newTagger: %w", sch.Name, err)
		}
		tagTime, err := timeOp(gbBenchReps, func() error { _, e := tagger.TagBlocks(store); return e })
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb tag: %w", sch.Name, err)
		}

		encoded := tagger.EncodedBlocks()
		clientSetup, err := tagger.ClientSetup()
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb clientSetup: %w", sch.Name, err)
		}
		proverSetup, err := tagger.ProverSetup()
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb proverSetup: %w", sch.Name, err)
		}
		challenger, err := sch.ChalFactory.NewChallenger(clientSetup, fixedChalSize)
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb newChallenger: %w", sch.Name, err)
		}
		prover, err := sch.ProvFactory.NewProver(proverSetup, encoded)
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb newProver: %w", sch.Name, err)
		}
		chal, _, err := challenger.Challenge(encoded.IDs())
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb challenge: %w", sch.Name, err)
		}

		proveTime, err := timeOp(gbBenchReps, func() error {
			_, e := prover.Prove(chal, encoded)
			return e
		})
		if err != nil {
			return GBProjectionData{}, fmt.Errorf("%s gb prove: %w", sch.Name, err)
		}

		tagV[i] = float64(tagTime)
		proveV[i] = float64(proveTime)
		fmt.Printf("  gb %s: tag=%dus prove=%dus\n", sch.Name, tagTime, proveTime)
	}

	return GBProjectionData{
		Schemes: names,
		Tag:     []BarGroup{{Label: "Tag", Color: "#64748b", Values: tagV}},
		Prove:   []BarGroup{{Label: "Prove", Color: "#3b82f6", Values: proveV}},
	}, nil
}

// sweepDetection estimates detection probability via Monte Carlo.
// It is separate from the main matrix because each trial varies which blocks
// are corrupted, not which protocol parameters are used.
func sweepDetection() (LineChart, error) {
	type detEntry struct {
		name, color string
		theoryC     int
		nEncoded    int
		encodedIDs  [][]byte
		clientSetup []byte
		prover      line.Prover
		honest      [][]byte
		chalFactory line.ChallengerFactory
	}

	rawBlocks := randomBlocksOfSize(detN, fixedBlockSz)
	rawStore := blockspkg.NewMemStore(rawBlocks)

	var entries []detEntry
	for _, sch := range schemes {
		fmt.Printf("  det setup %s\n", sch.Name)
		n, c := detN, detC
		store := rawStore
		if sch.Name == "BJO" {
			n, c = detBJONData, detBJOV
			store = blockspkg.NewMemStore(randomBlocksOfSize(n, fixedBlockSz))
		}
		tagger, err := sch.NewTagger(detKeyBits, c, fixedBlockSz, fixedSectorsPerBlock)
		if err != nil {
			return LineChart{}, fmt.Errorf("det %s: %w", sch.Name, err)
		}
		if _, err = tagger.TagBlocks(store); err != nil {
			return LineChart{}, fmt.Errorf("det %s tag: %w", sch.Name, err)
		}
		encoded := tagger.EncodedBlocks()
		cs, err := tagger.ClientSetup()
		if err != nil {
			return LineChart{}, err
		}
		ps, err := tagger.ProverSetup()
		if err != nil {
			return LineChart{}, err
		}
		prover, err := sch.ProvFactory.NewProver(ps, encoded)
		if err != nil {
			return LineChart{}, err
		}
		honest := encoded.(*blockspkg.MemStore).Blocks()
		entries = append(entries, detEntry{
			name: sch.Name, color: sch.color,
			theoryC: c, nEncoded: len(honest),
			encodedIDs:  encoded.IDs(),
			clientSetup: cs, prover: prover, honest: honest,
			chalFactory: sch.ChalFactory,
		})
	}

	type cellResult struct {
		hits int
		err  error
	}
	grid := make([][]cellResult, len(entries))
	for i := range entries {
		grid[i] = make([]cellResult, len(detFValues))
	}

	var wg sync.WaitGroup
	for i, entry := range entries {
		for j, f := range detFValues {
			wg.Add(1)
			go func(i int, entry detEntry, j int, f float64) {
				defer wg.Done()
				t := max(1, int(f*float64(entry.nEncoded)))
				hits := 0
				for range detTrials {
					corrupt := blockspkg.NewMemStore(corruptBlocks(entry.honest, randomSample(entry.nEncoded, t)))
					ch, err := entry.chalFactory.NewChallenger(entry.clientSetup, entry.theoryC)
					if err != nil {
						grid[i][j] = cellResult{err: err}
						return
					}
					chal, validator, err := ch.Challenge(entry.encodedIDs)
					if err != nil {
						grid[i][j] = cellResult{err: err}
						return
					}
					proof, err := entry.prover.Prove(chal, corrupt)
					if err != nil {
						grid[i][j] = cellResult{err: err}
						return
					}
					ok, err := validator.Verify(chal, proof)
					if err != nil {
						grid[i][j] = cellResult{err: err}
						return
					}
					if !ok {
						hits++
					}
				}
				grid[i][j] = cellResult{hits: hits}
			}(i, entry, j, f)
		}
	}
	wg.Wait()

	pts := map[string][]Point{}
	for i, entry := range entries {
		for j, f := range detFValues {
			if grid[i][j].err != nil {
				return LineChart{}, grid[i][j].err
			}
			pts[entry.name] = append(pts[entry.name], Point{f, float64(grid[i][j].hits) / float64(detTrials)})
		}
	}

	var series []Series
	for _, entry := range entries {
		n, c := entry.nEncoded, entry.theoryC
		series = append(series, Series{Label: entry.name, Color: entry.color, Points: pts[entry.name]})
		theory := make([]Point, len(detFValues))
		for i, f := range detFValues {
			t := max(1, int(f*float64(n)))
			theory[i] = Point{f, hypergeometricDetectionProb(n, c, t)}
		}
		series = append(series, Series{Label: entry.name + " (theory)", Color: entry.color, Dash: true, Points: theory})
	}
	return LineChart{XLabel: "Corruption fraction (f)", YLabel: "Detection probability", Series: series}, nil
}

// sweepExtraction counts how many valid witnesses are needed to passively
// extract the original file, averaged over extractReps trials, for each scheme
// that declares Cap.Extraction. The theory curve uses the generalized coupon
// collector formula E = N·H_N / L.
func sweepExtraction() (LineChart, error) {
	var series []Series
	for _, sch := range schemes {
		if !sch.Cap.Extraction {
			continue
		}
		var measured, theory []Point
		for _, n := range extractSweepN {
			store := blockspkg.NewMemStore(randomBlocks(n))
			var total int
			for range extractReps {
				count, err := countExtractionWitnesses(sch, store)
				if err != nil {
					return LineChart{}, fmt.Errorf("%s extraction n=%d: %w", sch.Name, n, err)
				}
				total += count
			}
			measured = append(measured, Point{float64(n), float64(total) / float64(extractReps)})

			// BJO's unknowns are the t inner-encoded blocks, not the n file blocks.
			theoryN := n
			if sch.Name == "BJO" {
				theoryN = bjoEncodedBlocks(n, bjoOuterN, bjoOuterK)
			}
			theory = append(theory, Point{float64(n), extractionProofsExpected(theoryN, fixedChalSize)})
		}
		series = append(series, Series{Label: sch.Name, Color: sch.color, Points: measured})
		series = append(series, Series{Label: sch.Name + " (theory)", Color: sch.color, Dash: true, Points: theory})
	}
	return LineChart{XLabel: "File blocks (N)", YLabel: "Witnesses to extract", Series: series}, nil
}

// countExtractionWitnesses runs one passive extraction trial: it drives
// challenge-response rounds and counts how many valid witnesses were required
// before Extract() succeeded.
func countExtractionWitnesses(sch schemeSpec, store blockspkg.BlockStore) (int, error) {
	tagger, err := sch.NewTagger(fixedKeyBits, fixedChalSize, fixedBlockSz, fixedSectorsPerBlock)
	if err != nil {
		return 0, err
	}
	if _, err = tagger.TagBlocks(store); err != nil {
		return 0, err
	}
	ep, ok := tagger.(line.ExtractorProducer)
	if !ok {
		return 0, fmt.Errorf("%s: does not implement ExtractorProducer", sch.Name)
	}
	extractor, err := ep.NewExtractor()
	if err != nil {
		return 0, err
	}
	proverSetup, err := tagger.ProverSetup()
	if err != nil {
		return 0, err
	}
	clientSetup, err := tagger.ClientSetup()
	if err != nil {
		return 0, err
	}
	encoded := tagger.EncodedBlocks()
	challenger, err := sch.ChalFactory.NewChallenger(clientSetup, fixedChalSize)
	if err != nil {
		return 0, err
	}
	prover, err := sch.ProvFactory.NewProver(proverSetup, encoded)
	if err != nil {
		return 0, err
	}

	witnesses := 0
	for range extractMaxRound {
		chal, validator, err := challenger.Challenge(encoded.IDs())
		if err != nil {
			return 0, err
		}
		proof, err := prover.Prove(chal, encoded)
		if err != nil {
			return 0, err
		}
		valid, err := validator.Verify(chal, proof)
		if err != nil {
			return 0, err
		}
		if valid {
			if err := extractor.Witness(chal, proof); err != nil {
				return 0, err
			}
			witnesses++
		}
		if _, err := extractor.Extract(); err == nil {
			return witnesses, nil
		} else if !errors.Is(err, line.ErrInsufficientProofs) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("%s: extraction did not converge within %d rounds", sch.Name, extractMaxRound)
}
