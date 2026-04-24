// pdpcharts runs empirical PDP simulations and writes an HTML file containing
// two interactive charts illustrating the protocol's statistical properties.
//
// Chart 1 — Per-challenge detection probability
//
//	X: challenge size C (blocks challenged per round)
//	Y: P(detect single corrupted block) = C/n
//	Shows theoretical lines for several file sizes and measured points for n=100.
//	Practical message: larger files need bigger challenges to maintain coverage.
//
// Chart 2 — Cumulative detection confidence
//
//	X: number of independent challenges run (k)
//	Y: P(detected at least once) = 1 − (1 − C/n)^k
//	Shows theoretical curves for several challenge-size fractions and measured
//	points for n=100, C=10.  Reference lines mark 90 / 95 / 99 % confidence.
//	Practical message: confidence compounds quickly even at modest per-round rates.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"text/template"

	"github.com/pinionengineering/storage-proofs/pdp"
)

const (
	keyBits   = 128 // small for speed; use ≥1024 in production
	simN      = 100 // total blocks in the simulated file
	blockSize = 256 // bytes per block
	trials    = 300 // empirical trials per data point
)

// xyPoint is a Chart.js-compatible {x, y} data point.
type xyPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// theorySeries is one labelled theoretical curve.
type theorySeries struct {
	Label  string    `json:"label"`
	Points []xyPoint `json:"points"`
	Color  string    `json:"color"`
}

// simState holds shared setup that all empirical runs reuse.
type simState struct {
	pk      *pdp.PublicKey
	sk      *pdp.SecretKey
	honest  [][]byte
	corrupt [][]byte // identical to honest except at badIdx
	tags    []*pdp.Tag
	badIdx  int
}

func newSimState() (*simState, error) {
	fmt.Fprint(os.Stderr, "Generating keys...")
	pk, sk, err := pdp.KeyGen(keyBits)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, " done.")

	fmt.Fprintf(os.Stderr, "Tagging %d blocks...", simN)
	honest := make([][]byte, simN)
	tags := make([]*pdp.Tag, simN)
	for i := range simN {
		honest[i] = make([]byte, blockSize)
		if _, err = rand.Read(honest[i]); err != nil {
			return nil, err
		}
		w := binary.BigEndian.AppendUint64(append([]byte(nil), sk.V...), uint64(i))
		tags[i], err = pdp.SuiteV1.TagBlock(pk, sk, honest[i], w)
		if err != nil {
			return nil, err
		}
	}
	fmt.Fprintln(os.Stderr, " done.")

	bidxBig, err := rand.Int(rand.Reader, big.NewInt(int64(simN)))
	if err != nil {
		return nil, err
	}
	badIdx := int(bidxBig.Int64())

	corrupt := make([][]byte, simN)
	copy(corrupt, honest)
	corrupt[badIdx] = make([]byte, blockSize)
	if _, err = rand.Read(corrupt[badIdx]); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Corrupted block: #%d\n", badIdx)
	return &simState{pk, sk, honest, corrupt, tags, badIdx}, nil
}

// runChallenge issues one challenge of size c against blocks and returns
// whether the verifier accepted (true) or rejected (false = detected corrupt).
func (s *simState) runChallenge(blocks [][]byte, c int) (bool, error) {
	secret, err := rand.Int(rand.Reader, s.pk.N)
	if err != nil {
		return false, err
	}
	Gs := new(big.Int).Exp(s.pk.G, secret, s.pk.N)
	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	if _, err = rand.Read(k1); err != nil {
		return false, err
	}
	if _, err = rand.Read(k2); err != nil {
		return false, err
	}
	chal := &pdp.Challenge{
		SuiteID: pdp.SuiteV1.ID(),
		C:       c,
		K1:      k1,
		K2:      k2,
		Gs:      Gs,
	}
	proof, err := pdp.SuiteV1.GenProof(s.pk, blocks, chal, s.tags)
	if err != nil {
		return false, err
	}
	return pdp.SuiteV1.CheckProof(s.pk, s.sk, secret, s.tags, chal, proof)
}

// chart1Empirical measures empirical P(detect) for varying C, with n=simN.
func chart1Empirical(s *simState) ([]xyPoint, error) {
	fmt.Fprintln(os.Stderr, "Chart 1: measuring per-challenge detection rates...")

	var cValues []int
	for c := 1; c <= simN; c += 5 {
		cValues = append(cValues, c)
	}
	if cValues[len(cValues)-1] != simN {
		cValues = append(cValues, simN)
	}

	pts := make([]xyPoint, 0, len(cValues))
	for _, c := range cValues {
		detected := 0
		for range trials {
			ok, err := s.runChallenge(s.corrupt, c)
			if err != nil {
				return nil, err
			}
			if !ok {
				detected++
			}
		}
		obs := float64(detected) / float64(trials)
		theory := float64(c) / float64(simN)
		fmt.Fprintf(os.Stderr, "  C=%-3d  obs=%.3f  theory=%.3f\n", c, obs, theory)
		pts = append(pts, xyPoint{X: float64(c), Y: obs})
	}
	return pts, nil
}

// chart2Empirical measures empirical cumulative detection for n=simN, C=c,
// over k=1..50 rounds.
func chart2Empirical(s *simState, c int) ([]xyPoint, error) {
	fmt.Fprintf(os.Stderr, "Chart 2: measuring cumulative detection (C=%d)...\n", c)

	const maxK = 50
	pts := make([]xyPoint, 0, maxK)
	for k := 1; k <= maxK; k++ {
		detected := 0
		for range trials {
			caught := false
			for range k {
				ok, err := s.runChallenge(s.corrupt, c)
				if err != nil {
					return nil, err
				}
				if !ok {
					caught = true
					break
				}
			}
			if caught {
				detected++
			}
		}
		pts = append(pts, xyPoint{
			X: float64(k),
			Y: float64(detected) / float64(trials),
		})
		fmt.Fprintf(os.Stderr, "  k=%-3d  obs=%.3f  theory=%.3f\n",
			k,
			float64(detected)/float64(trials),
			1-math.Pow(1-float64(c)/float64(simN), float64(k)),
		)
	}
	return pts, nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

const chartJSURL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"

// fetchChartJS downloads the Chart.js bundle and returns it as a string.
// If the download fails the program exits, because without it the HTML is useless.
func fetchChartJS() string {
	fmt.Fprint(os.Stderr, "Downloading Chart.js...")
	resp, err := http.Get(chartJSURL) //nolint:gosec // URL is a constant
	if err != nil {
		fmt.Fprintf(os.Stderr, " FAILED: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, " FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, " done (%d KB).\n", len(body)/1024)
	return string(body)
}

func main() {
	s, err := newSimState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}

	// ── Chart 1 theory: P = C/n for various file sizes ──────────────────────
	type theorySpec struct{ n int; color string }
	specs := []theorySpec{
		{50, "#3b82f6"},
		{100, "#8b5cf6"},
		{500, "#ec4899"},
		{1000, "#f97316"},
	}
	chart1Theory := make([]theorySeries, 0, len(specs))
	for _, sp := range specs {
		pts := []xyPoint{{0, 0}}
		for c := 1; c <= sp.n; c++ {
			pts = append(pts, xyPoint{float64(c), float64(c) / float64(sp.n)})
		}
		chart1Theory = append(chart1Theory, theorySeries{
			Label:  fmt.Sprintf("Theory — n=%d blocks", sp.n),
			Points: pts,
			Color:  sp.color,
		})
	}

	chart1Emp, err := chart1Empirical(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// ── Chart 2 theory: 1−(1−r)^k for various challenge fractions ───────────
	type fracSpec struct {
		r     float64
		label string
		color string
	}
	fracs := []fracSpec{
		{0.01, "1% of blocks per challenge", "#94a3b8"},
		{0.05, "5% of blocks per challenge", "#3b82f6"},
		{0.10, "10% of blocks per challenge", "#8b5cf6"},
		{0.20, "20% of blocks per challenge", "#ec4899"},
		{0.50, "50% of blocks per challenge", "#f97316"},
	}
	chart2Theory := make([]theorySeries, 0, len(fracs))
	for _, fs := range fracs {
		pts := make([]xyPoint, 0, 101)
		for k := 0; k <= 100; k++ {
			pts = append(pts, xyPoint{float64(k), 1 - math.Pow(1-fs.r, float64(k))})
		}
		chart2Theory = append(chart2Theory, theorySeries{
			Label:  fs.label,
			Points: pts,
			Color:  fs.color,
		})
	}

	const chart2C = 10 // empirical simulation uses C=10 (10% of simN=100)
	chart2Emp, err := chart2Empirical(s, chart2C)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// ── Write HTML ────────────────────────────────────────────────────────────
	chartJS := fetchChartJS()

	type tmplData struct {
		SimN         int
		BadIdx       int
		Chart2C      int
		ChartJS      string // inlined Chart.js bundle
		Chart1Theory string
		Chart1Emp    string
		Chart2Theory string
		Chart2Emp    string
	}

	data := tmplData{
		SimN:         simN,
		BadIdx:       s.badIdx,
		Chart2C:      chart2C,
		ChartJS:      chartJS,
		Chart1Theory: mustJSON(chart1Theory),
		Chart1Emp:    mustJSON(chart1Emp),
		Chart2Theory: mustJSON(chart2Theory),
		Chart2Emp:    mustJSON(chart2Emp),
	}

	outPath := "pdp_charts.html"
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := pageTemplate.Execute(f, data); err != nil {
		f.Close()
		fmt.Fprintln(os.Stderr, "template:", err)
		os.Exit(1)
	}
	f.Close()
	fmt.Println("Charts written to:", outPath)
	fmt.Println("Open it in a browser to view.")
}

var pageTemplate = template.Must(template.New("page").Parse(htmlPage))

const htmlPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PDP Statistical Properties</title>
<script>{{.ChartJS}}</script>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  html { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }
  body { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { font-size: 1.6rem; font-weight: 700; color: #f1f5f9; margin: 0 0 .25rem; }
  .subtitle { color: #94a3b8; font-size: .9rem; margin-bottom: 2.5rem; }
  .subtitle strong { color: #cbd5e1; }
  section { background: #1e293b; border: 1px solid #334155; border-radius: .75rem;
            padding: 1.5rem 1.75rem; margin-bottom: 2rem; }
  h2 { font-size: 1.1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 .4rem; }
  .desc { color: #94a3b8; font-size: .85rem; line-height: 1.55; margin: 0 0 1.25rem; }
  .desc strong { color: #cbd5e1; }
  .desc code { background: #0f172a; padding: .1em .35em; border-radius: .25em;
               font-size: .9em; color: #a78bfa; }
  .chart-wrap { position: relative; height: 400px; }
</style>
</head>
<body>

<h1>PDP Protocol — Statistical Detection Properties</h1>
<p class="subtitle">
  Simulation: <strong>{{.SimN}} blocks</strong> &middot;
  one corrupted block (<strong>#{{.BadIdx}}</strong>) &middot;
  {{.SimN | printf "%d"}} tags &middot; key size 128 bits (test mode, use &ge;1024 in production)
</p>

<section>
  <h2>1 &mdash; Single-Challenge Detection Probability</h2>
  <p class="desc">
    When a verifier issues a challenge that samples <em>C</em> blocks at random from
    a file of <em>n</em> blocks, and the server is hiding exactly one corrupted block,
    the probability of detection is <strong>P = C / n</strong>.
    Larger files require proportionally larger challenges to maintain the same coverage.
    The green dots are measured results from this run; they should lie on the
    <strong>Theory &mdash; n={{.SimN}}</strong> line.
  </p>
  <div class="chart-wrap"><canvas id="c1"></canvas></div>
</section>

<section>
  <h2>2 &mdash; Cumulative Detection Confidence</h2>
  <p class="desc">
    Running <em>k</em> independent challenges, the probability of catching the corrupted
    block <em>at least once</em> is <strong>1 &minus; (1 &minus; C/n)<sup>k</sup></strong>.
    Even a 1&percnt;-per-challenge detection rate reaches 63&percnt; after 100 rounds
    and can be pushed arbitrarily close to certainty by running more challenges.
    Dashed lines mark 90&percnt;, 95&percnt;, and 99&percnt; confidence thresholds.
    The green dots are measured results for <code>n={{.SimN}}, C={{.Chart2C}}</code>.
  </p>
  <div class="chart-wrap"><canvas id="c2"></canvas></div>
</section>

<script>
"use strict";
const chart1Theory = {{.Chart1Theory}};
const chart1Emp    = {{.Chart1Emp}};
const chart2Theory = {{.Chart2Theory}};
const chart2Emp    = {{.Chart2Emp}};
const simN         = {{.SimN}};
const chart2C      = {{.Chart2C}};

// ── shared helpers ────────────────────────────────────────────────────────────
const pctTick = v => (v * 100).toFixed(0) + '%';

const empDataset = (label, data) => ({
  label,
  data,
  borderColor:      '#10b981',
  backgroundColor:  '#10b981',
  pointRadius:      5,
  pointHoverRadius: 8,
  showLine:         false,
});

const theoryDataset = s => ({
  label:           s.label,
  data:            s.points,
  borderColor:     s.color,
  backgroundColor: 'transparent',
  pointRadius:     0,
  showLine:        true,
  fill:            false,
  tension:         0,
  borderWidth:     1.8,
});

// ── Chart 1 ───────────────────────────────────────────────────────────────────
new Chart(document.getElementById('c1'), {
  type: 'scatter',
  data: {
    datasets: [
      ...chart1Theory.map(theoryDataset),
      empDataset('Measured \u2014 n=' + simN + ' (one corrupt block)', chart1Emp),
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      title: {
        display: true,
        text: 'P(detect) per single challenge  =  C / n',
        color: '#f1f5f9',
        font: { size: 14, weight: '600' },
        padding: { bottom: 14 },
      },
      legend: {
        position: 'right',
        labels: { color: '#94a3b8', boxWidth: 20, padding: 14 },
      },
      tooltip: {
        callbacks: {
          label: ctx => {
            const pct = (ctx.parsed.y * 100).toFixed(1);
            return ' C=' + ctx.parsed.x + ' blocks \u2192 P=' + pct + '%';
          },
        },
      },
    },
    scales: {
      x: {
        type: 'linear',
        title: {
          display: true,
          text: 'Challenge size  C  (blocks sampled per round)',
          color: '#94a3b8',
          font: { size: 12 },
        },
        min: 0,
        ticks: { color: '#64748b' },
        grid:  { color: '#1e293b' },
      },
      y: {
        title: {
          display: true,
          text: 'Detection probability (one challenge)',
          color: '#94a3b8',
          font: { size: 12 },
        },
        min: 0, max: 1,
        ticks: { callback: pctTick, color: '#64748b' },
        grid:  { color: '#334155' },
      },
    },
  },
});

// ── Chart 2 ───────────────────────────────────────────────────────────────────
const refLines = [
  { y: 0.90, label: '90% confidence', color: '#475569' },
  { y: 0.95, label: '95% confidence', color: '#64748b' },
  { y: 0.99, label: '99% confidence', color: '#94a3b8' },
];

const refDataset = r => ({
  label:       r.label,
  data:        [{ x: 0, y: r.y }, { x: 100, y: r.y }],
  borderColor: r.color,
  borderDash:  [5, 4],
  borderWidth: 1,
  pointRadius: 0,
  showLine:    true,
  fill:        false,
});

new Chart(document.getElementById('c2'), {
  type: 'scatter',
  data: {
    datasets: [
      ...chart2Theory.map(theoryDataset),
      empDataset(
        'Measured \u2014 n=' + simN + ', C=' + chart2C + ' blocks/challenge',
        chart2Emp,
      ),
      ...refLines.map(refDataset),
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      title: {
        display: true,
        text: 'Cumulative confidence after k challenges  =  1 − (1 − C/n)^k',
        color: '#f1f5f9',
        font: { size: 14, weight: '600' },
        padding: { bottom: 14 },
      },
      legend: {
        position: 'right',
        labels: { color: '#94a3b8', boxWidth: 20, padding: 14 },
      },
      tooltip: {
        callbacks: {
          label: ctx => {
            const pct = (ctx.parsed.y * 100).toFixed(1);
            return ' k=' + ctx.parsed.x + ' rounds \u2192 P=' + pct + '%';
          },
        },
      },
    },
    scales: {
      x: {
        type: 'linear',
        title: {
          display: true,
          text: 'Challenges run  (k)',
          color: '#94a3b8',
          font: { size: 12 },
        },
        min: 0, max: 50,
        ticks: { color: '#64748b' },
        grid:  { color: '#1e293b' },
      },
      y: {
        title: {
          display: true,
          text: 'Cumulative detection probability',
          color: '#94a3b8',
          font: { size: 12 },
        },
        min: 0, max: 1,
        ticks: { callback: pctTick, color: '#64748b' },
        grid:  { color: '#334155' },
      },
    },
  },
});
</script>
</body>
</html>
`
