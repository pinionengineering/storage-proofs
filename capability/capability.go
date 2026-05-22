// Package capability defines the canonical registry of storage-proof schemes
// and the capability flags that describe which optional protocol properties
// each scheme supports. Tests in this package verify those claims.
package capability

import (
	"math/big"
	"sync"

	"github.com/pinionengineering/storage-proofs/line"
	lineAteniese "github.com/pinionengineering/storage-proofs/line/ateniese"
	lineBJO "github.com/pinionengineering/storage-proofs/line/bjo"
	lineErway "github.com/pinionengineering/storage-proofs/line/erway"
	lineSW "github.com/pinionengineering/storage-proofs/line/sw"
	lineSwPub "github.com/pinionengineering/storage-proofs/line/swpub"
	pdpateniese "github.com/pinionengineering/storage-proofs/pdp/ateniese"
	pdperway "github.com/pinionengineering/storage-proofs/pdp/erway"
	porbjo "github.com/pinionengineering/storage-proofs/por/bjo"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

const (
	bjoOuterN = 8
	bjoOuterK = 4
	bjoW      = 20
	bjoQ      = 10
	swS       = 4
)

var (
	swP = func() *big.Int {
		p, _ := new(big.Int).SetString("340282366920938463463374607431768211507", 10)
		return p
	}()
	bjoP = big.NewInt(2147483647)
)

// SetupTagger combines line.Tagger and line.SetupProducer, which all scheme
// taggers implement after TagBlocks has been called.
type SetupTagger interface {
	line.Tagger
	line.SetupProducer
}

// Cap describes which optional protocol properties a scheme supports.
type Cap struct {
	SparseBlocks bool // supports non-sequential block identifiers
}

// SchemeSpec describes one storage-proof scheme using the line interfaces.
type SchemeSpec struct {
	Name        string
	NewTagger   func(keyBits, chalSize int) (SetupTagger, error)
	ChalFactory line.ChallengerFactory
	ProvFactory line.ProverFactory
	Cap         Cap
}

// Schemes is the canonical list of all implemented storage-proof schemes.
var Schemes = []SchemeSpec{
	{
		Name: "Ateniese",
		Cap:  Cap{SparseBlocks: true},
		NewTagger: func() func(int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(keyBits, _ int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[keyBits]
				if !ok {
					pk, sk, err := pdpateniese.KeyGen(keyBits)
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineAteniese.NewTagger(pk, sk, suite.SuiteV1), nil
					}
					cache[keyBits] = fn
				}
				return fn()
			}
		}(),
		ChalFactory: lineAteniese.NewChallengerFactory(),
		ProvFactory: lineAteniese.NewProverFactory(),
	},
	{
		Name: "Erway",
		Cap:  Cap{SparseBlocks: false},
		NewTagger: func() func(int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(keyBits, _ int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[keyBits]
				if !ok {
					pk, err := pdperway.KeyGen(keyBits)
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineErway.NewTagger(pk, suite.SuiteV1), nil
					}
					cache[keyBits] = fn
				}
				return fn()
			}
		}(),
		ChalFactory: lineErway.NewChallengerFactory(),
		ProvFactory: lineErway.NewProverFactory(suite.SuiteV1),
	},
	{
		Name: "SW-Priv",
		Cap:  Cap{SparseBlocks: true},
		NewTagger: func() func(int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(_, chalSize int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[chalSize]
				if !ok {
					sk, err := porsw.KeyGen(&porsw.Params{S: swS, L: chalSize, P: swP})
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineSW.NewTagger(sk, suite.SuiteV1), nil
					}
					cache[chalSize] = fn
				}
				return fn()
			}
		}(),
		ChalFactory: lineSW.NewChallengerFactory(),
		ProvFactory: lineSW.NewProverFactory(),
	},
	{
		Name: "BJO",
		Cap:  Cap{SparseBlocks: false},
		NewTagger: func() func(int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(_, chalSize int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[chalSize]
				if !ok {
					mk, err := porbjo.KeyGen(&porbjo.Params{
						V: chalSize, W: bjoW, Q: bjoQ, P: bjoP,
						OuterN: bjoOuterN, OuterK: bjoOuterK,
					})
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineBJO.NewTagger(mk, suite.SuiteV1), nil
					}
					cache[chalSize] = fn
				}
				return fn()
			}
		}(),
		ChalFactory: lineBJO.NewChallengerFactory(),
		ProvFactory: lineBJO.NewProverFactory(suite.SuiteV1),
	},
	{
		Name: "SW-Pub",
		Cap:  Cap{SparseBlocks: true},
		NewTagger: func() func(int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(_, chalSize int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				fn, ok := cache[chalSize]
				if !ok {
					ps, err := porsw.NewPubScheme(swS, chalSize)
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineSwPub.NewTagger(ps, suite.SuiteV1), nil
					}
					cache[chalSize] = fn
				}
				return fn()
			}
		}(),
		ChalFactory: lineSwPub.NewChallengerFactory(),
		ProvFactory: lineSwPub.NewProverFactory(),
	},
}
