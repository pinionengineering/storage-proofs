// study benchmarks all five storage-proof schemes and writes a self-contained
// study.html with measured data overlaid on theoretical scaling curves.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// Constants and parameters
// ---------------------------------------------------------------------------

const (
	fixedKeyBits         = 1024
	fixedNBlocks         = 40
	fixedChalSize        = 5
	fixedBlockSz         = 32 // raw block size for Ateniese/Erway/SW-*; see bjoBlockSz for BJO
	fixedSectorsPerBlock = 64 // S for SW-Priv/SW-Pub; other schemes ignore it
	benchReps            = 3

	// bjoBlockSz is BJO's raw block size. Unlike SW-Priv/SW-Pub, BJO has no
	// sub-block partitioning -- a whole block is one Z_P element (see
	// capability.go's NewTagger: bjoPForBlockSize grows P to exceed it, and
	// SectorsPerBlock is ignored). fixedBlockSz would make P ~256 bits;
	// bjoBlockSz keeps it near the ~31-bit field this study's theory
	// formulas already assume (bjoPLen, bjoP below).
	bjoBlockSz = 4

	bjoOuterN = 8
	bjoOuterK = 4
	bjoW      = 20
	bjoQ      = 10
	swS       = 4

	// byte lengths for wire-size theory formulas
	swPLen  = 16 // 128-bit prime
	bjoPLen = 4  // 31-bit prime (2^31-1)

	// detection sweep
	detN       = 100
	detC       = 20
	detKeyBits = 128
	detTrials  = 30

	// extraction sweep
	extractMaxRound = 600 // generous margin over E[witnesses]≈236 for N=100 BJO
	extractReps     = 3

	// BJO detection uses smaller parameters for speed
	detBJONData  = 40
	detBJOV      = 10
	detBJOOuterN = 8
	detBJOOuterK = 4

	// gbProjectionBytes is the target content size for the "time to tag/prove
	// N bytes" bar charts: a real measurement at this size for every scheme,
	// all using the same block size (gbBlockSize in sweep.go) so schemes are
	// compared on equal footing -- not an extrapolation from the smaller N
	// used elsewhere in this file. 100MB rather than a full GB keeps the
	// resulting block count (gbProjectionBytes/gbBlockSize, the same for
	// every scheme) practical to actually execute.
	gbProjectionBytes = 100_000_000

	// gbBenchReps is deliberately 1: a single real measurement at this scale
	// is expensive enough that repeating it for noise reduction isn't worth
	// the added run time.
	gbBenchReps = 1
)

var (
	keySweepBits  = []int{128, 512, 1024}
	fileSweepN    = []int{20, 40, 80, 200}
	extractSweepN = []int{10, 20, 30, 40, 60, 80, 100}
	chalSweepC    = []int{1, 5, 10, 20, 40}

	// blockSizeSweep varies raw block size at a fixed N and C to show how
	// each scheme's cost scales with block size directly -- the axis the
	// study previously never plotted, despite it being a first-order cost
	// driver for every scheme without SW's sector subdivision. Capped at
	// 1984 bytes so SW-Pub's ceilDiv(blockSize, fixedSectorsPerBlock)
	// sector-byte constraint (MaxSWPubSectorBytes=31) is never violated.
	blockSizeSweep = []int{16, 32, 64, 128, 256, 512, 1024, 1984}
	detFValues     = []float64{0.01, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50}

	swP = func() *big.Int {
		p, _ := new(big.Int).SetString("340282366920938463463374607431768211507", 10)
		return p
	}()
	bjoP = big.NewInt(2147483647)
)

//go:embed study.tmpl
var studyTmpl string

// ---------------------------------------------------------------------------
// Chart data types
// ---------------------------------------------------------------------------

type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type Series struct {
	Label  string  `json:"label"`
	Color  string  `json:"color"`
	Dash   bool    `json:"dash"`
	Points []Point `json:"points"`
}

type LineChart struct {
	XLabel string   `json:"xlabel"`
	YLabel string   `json:"ylabel"`
	Series []Series `json:"series"`
}

type BarGroup struct {
	Label  string    `json:"label"`
	Color  string    `json:"color"`
	Values []float64 `json:"values"`
}

type SuiteSweepData struct {
	Schemes []string   `json:"schemes"`
	Setup   []BarGroup `json:"setup"`
	Prove   []BarGroup `json:"prove"`
	Verify  []BarGroup `json:"verify"`
}

// GBProjectionData holds the real (not extrapolated) tag/prove CPU time
// measured for each scheme at gbProjectionBytes, all using the same block
// size — see gbBlockSize in sweep.go.
type GBProjectionData struct {
	Schemes []string   `json:"schemes"`
	Tag     []BarGroup `json:"tag"`
	Prove   []BarGroup `json:"prove"`
}

type Charts struct {
	TagTime         LineChart        `json:"tagTime"`
	ProveTime       LineChart        `json:"proveTime"`
	VerifyTime      LineChart        `json:"verifyTime"`
	ChalBytes       LineChart        `json:"chalBytes"`
	ProofBytes      LineChart        `json:"proofBytes"`
	KeySweep        LineChart        `json:"keySweep"`
	BlockSizeSetup  LineChart        `json:"blockSizeSetup"`
	BlockSizeProve  LineChart        `json:"blockSizeProve"`
	BlockSizeVerify LineChart        `json:"blockSizeVerify"`
	Detection       LineChart        `json:"detection"`
	Extraction      LineChart        `json:"extraction"`
	SuiteSweep      SuiteSweepData   `json:"suiteSweep"`
	GBProjection    GBProjectionData `json:"gbProjection"`
}

type SchemeCapability struct {
	Name         string `json:"name"`
	Color        string `json:"color"`
	SparseBlocks bool   `json:"sparse_blocks"`
	Extraction   bool   `json:"extraction"`
}

type StudyData struct {
	Date         string             `json:"date"`
	Charts       Charts             `json:"charts"`
	Capabilities []SchemeCapability `json:"capabilities"`
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	charts, err := runSweep()
	if err != nil {
		log.Fatal(err)
	}
	caps := make([]SchemeCapability, len(schemes))
	for i, sch := range schemes {
		caps[i] = SchemeCapability{Name: sch.Name, Color: sch.color,
			SparseBlocks: sch.Cap.SparseBlocks, Extraction: sch.Cap.Extraction}
	}
	data := StudyData{Date: time.Now().Format("2006-01-02"), Charts: *charts, Capabilities: caps}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}
	tmpl, err := template.New("study").Parse(studyTmpl)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create("study.html")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	payload := struct {
		Date              string
		DataJSON          template.JS
		GBProjectionBytes int
	}{data.Date, template.JS(jsonBytes), gbProjectionBytes}
	if err = tmpl.Execute(f, payload); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote study.html")
}
