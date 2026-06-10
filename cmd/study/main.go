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
	fixedKeyBits  = 1024
	fixedNBlocks  = 40
	fixedChalSize = 5
	fixedBlockSz  = 32
	benchReps     = 3

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
)

var (
	keySweepBits  = []int{128, 512, 1024}
	fileSweepN    = []int{20, 40, 80, 200}
	extractSweepN = []int{10, 20, 30, 40, 60, 80, 100}
	chalSweepC   = []int{1, 5, 10, 20, 40}
	detFValues   = []float64{0.01, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50}

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

type Charts struct {
	TagTime    LineChart      `json:"tagTime"`
	ProveTime  LineChart      `json:"proveTime"`
	VerifyTime LineChart      `json:"verifyTime"`
	ChalBytes  LineChart      `json:"chalBytes"`
	ProofBytes LineChart      `json:"proofBytes"`
	KeySweep   LineChart      `json:"keySweep"`
	Detection  LineChart      `json:"detection"`
	Extraction LineChart      `json:"extraction"`
	SuiteSweep SuiteSweepData `json:"suiteSweep"`
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
		Date     string
		DataJSON template.JS
	}{data.Date, template.JS(jsonBytes)}
	if err = tmpl.Execute(f, payload); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote study.html")
}
