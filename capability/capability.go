// Package capability defines the canonical registry of storage-proof schemes
// and the capability flags that describe which optional protocol properties
// each scheme supports. Tests in this package verify those claims.
package capability

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/pinionengineering/storage-proofs/line"
	lineAteniese "github.com/pinionengineering/storage-proofs/line/ateniese"
	lineBJO "github.com/pinionengineering/storage-proofs/line/bjo"
	lineErway "github.com/pinionengineering/storage-proofs/line/erway"
	lineSW "github.com/pinionengineering/storage-proofs/line/sw"
	lineSwPub "github.com/pinionengineering/storage-proofs/line/swpub"
	"github.com/pinionengineering/storage-proofs/pdp"
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
	bjoQ      = 500 // must exceed expected witnesses for extraction; N=100 needs ~236 in the study sweep

	testBlockSize = 32 // byte length of blocks used in capability tests

	// MaxSWPubSectorBytes is the largest sector byte size safe for SW-Pub:
	// a sector is interpreted as a scalar mod the BN254 group order (a fixed,
	// ~254-bit prime — not a caller choice), so every possible T-byte value
	// must stay strictly below it. 31 bytes (248 bits) is the largest T with
	// 2^(8T)-1 guaranteed less than the order for any 31-byte value; 32 bytes
	// would let some values reach or exceed it, breaking the injective
	// raw-bytes-to-field-element mapping extraction depends on. Exported so
	// callers choosing a blockSize/sectorsPerBlock pair can size against it.
	MaxSWPubSectorBytes = 31
)

// swPForSectorBytes returns a random prime with enough bits to exceed the
// maximum value of a sectorBytes-byte sector (P > 2^(8*sectorBytes)). SW-Priv
// treats each sector as a single Z_P element, so P must be larger than any
// sector value for the extraction property to hold regardless of sector size.
// Mirrors bjoPForBlockSize below.
func swPForSectorBytes(sectorBytes int) (*big.Int, error) {
	p, err := rand.Prime(rand.Reader, sectorBytes*8+1)
	if err != nil {
		return nil, fmt.Errorf("capability: swPForSectorBytes(%d): %w", sectorBytes, err)
	}
	return p, nil
}

// ceilDiv mirrors the sector-byte-size math done inside por/sw's sectorElem /
// pubSectorElem, so P (SW-Priv) and the T<=31 guard (SW-Pub) are checked
// against the same worst-case sector size those functions will actually use.
func ceilDiv(a, b int) int { return (a + b - 1) / b }

// bjoPForBlockSize returns a random prime with enough bits to exceed the
// maximum value of a blockBytes-byte block (P > 2^(8·blockBytes)). BJO treats
// each encoded block as a single Z_P element, so P must be larger than any
// block value for the extraction property to hold regardless of block size.
func bjoPForBlockSize(blockBytes int) (*big.Int, error) {
	p, err := rand.Prime(rand.Reader, blockBytes*8+1)
	if err != nil {
		return nil, fmt.Errorf("capability: bjoPForBlockSize(%d): %w", blockBytes, err)
	}
	return p, nil
}

// SetupTagger combines line.Tagger and line.SetupProducer, which all scheme
// taggers implement after TagBlocks has been called.
type SetupTagger interface {
	line.Tagger
	line.SetupProducer
}

// taggerCacheKey caches a constructed Tagger by every parameter that
// determines its key material, so distinct configurations never collide.
// sectorsPerBlock is unused (left zero) for schemes that don't sector-split
// blocks (BJO).
type taggerCacheKey struct {
	chalSize        int
	blockSize       int
	sectorsPerBlock int
}

// Cap describes which optional protocol properties a scheme supports.
type Cap struct {
	SparseBlocks bool // supports non-sequential block identifiers
	Extraction   bool // supports file recovery via line.ExtractorProducer
}

// SchemeSpec describes one storage-proof scheme using the line interfaces.
type SchemeSpec struct {
	Name string

	// NewTagger constructs a Tagger for this scheme. blockSize and
	// sectorsPerBlock are only meaningful for schemes whose key material is
	// sized against a caller-chosen block size (SW-Priv, SW-Pub, BJO) —
	// schemes without such a requirement ignore both (Ateniese, Erway).
	// blockSize is the exact byte size of every block the caller's
	// blocks.BlockStore will present (the same value the caller uses to
	// configure its block-size virtualization layer). For SW-Priv/SW-Pub,
	// sectorsPerBlock (S) additionally divides each block into S sectors of
	// ceil(blockSize/S) bytes each — see por/sw's sectorElem; BJO ignores
	// sectorsPerBlock since it treats a whole block as one Z_P element.
	NewTagger   func(keyBits, chalSize, blockSize, sectorsPerBlock int) (SetupTagger, error)
	ChalFactory line.ChallengerFactory
	ProvFactory line.ProverFactory
	Cap         Cap

	// MarshalTagger serializes the full key material of a Tagger — including
	// secrets — for persistent server-side storage (e.g. GCS). The blob includes
	// the suite ID so UnmarshalTagger can reconstruct the exact same Tagger.
	// nil for schemes that do not support server-side key persistence (Erway, BJO, Ateniese).
	MarshalTagger func(SetupTagger) ([]byte, error)

	// UnmarshalTagger reconstructs a Tagger from a blob produced by MarshalTagger.
	// The reconstructed Tagger uses the same key material as the original, so
	// new blocks tagged with it remain verifiable with the same ClientSetup.
	// nil for schemes that do not support server-side key persistence.
	UnmarshalTagger func([]byte) (SetupTagger, error)
}

// taggerKeyWire is the JSON envelope for single-key MarshalTagger / UnmarshalTagger
// blobs (SW-Priv, SW-Pub, BJO). Key is stored as json.RawMessage so the key object
// is embedded inline rather than base64-encoded.
type taggerKeyWire struct {
	SuiteID uint8           `json:"suite_id"`
	Key     json.RawMessage `json:"key"`
}

func swPubMarshalTagger(t SetupTagger) ([]byte, error) {
	st, ok := t.(*lineSwPub.Tagger)
	if !ok {
		return nil, fmt.Errorf("swpub: MarshalTagger: unexpected Tagger type %T", t)
	}
	key, err := json.Marshal(st.PubScheme())
	if err != nil {
		return nil, fmt.Errorf("swpub: MarshalTagger: %w", err)
	}
	return json.Marshal(taggerKeyWire{SuiteID: suite.SuiteV1.ID(), Key: key})
}

func swPubUnmarshalTagger(data []byte) (SetupTagger, error) {
	var w taggerKeyWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("swpub: UnmarshalTagger: %w", err)
	}
	s, ok := suite.SuiteByID(w.SuiteID)
	if !ok {
		return nil, fmt.Errorf("swpub: UnmarshalTagger: unknown suite %d", w.SuiteID)
	}
	var ps porsw.PubScheme
	if err := json.Unmarshal(w.Key, &ps); err != nil {
		return nil, fmt.Errorf("swpub: UnmarshalTagger: %w", err)
	}
	return lineSwPub.NewTagger(&ps, s), nil
}

func swPrivMarshalTagger(t SetupTagger) ([]byte, error) {
	st, ok := t.(*lineSW.Tagger)
	if !ok {
		return nil, fmt.Errorf("sw: MarshalTagger: unexpected Tagger type %T", t)
	}
	key, err := json.Marshal(st.SecretKey())
	if err != nil {
		return nil, fmt.Errorf("sw: MarshalTagger: %w", err)
	}
	return json.Marshal(taggerKeyWire{SuiteID: suite.SuiteV1.ID(), Key: key})
}

func swPrivUnmarshalTagger(data []byte) (SetupTagger, error) {
	var w taggerKeyWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("sw: UnmarshalTagger: %w", err)
	}
	s, ok := suite.SuiteByID(w.SuiteID)
	if !ok {
		return nil, fmt.Errorf("sw: UnmarshalTagger: unknown suite %d", w.SuiteID)
	}
	var sk porsw.SecretKey
	if err := json.Unmarshal(w.Key, &sk); err != nil {
		return nil, fmt.Errorf("sw: UnmarshalTagger: %w", err)
	}
	return lineSW.NewTagger(&sk, s), nil
}

// ateniesesMarshalTagger serializes an Ateniese Tagger's full key (pk N,G + sk E,D,V,Phi).
func ateniesesMarshalTagger(t SetupTagger) ([]byte, error) {
	st, ok := t.(*lineAteniese.Tagger)
	if !ok {
		return nil, fmt.Errorf("ateniese: MarshalTagger: unexpected Tagger type %T", t)
	}
	pkData, err := json.Marshal(st.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("ateniese: MarshalTagger: pk: %w", err)
	}
	skData, err := json.Marshal(st.SecretKey())
	if err != nil {
		return nil, fmt.Errorf("ateniese: MarshalTagger: sk: %w", err)
	}
	type wire struct {
		SuiteID uint8           `json:"suite_id"`
		PK      json.RawMessage `json:"pk"`
		SK      json.RawMessage `json:"sk"`
	}
	return json.Marshal(wire{SuiteID: suite.SuiteV1.ID(), PK: pkData, SK: skData})
}

func ateniesesUnmarshalTagger(data []byte) (SetupTagger, error) {
	type wire struct {
		SuiteID uint8           `json:"suite_id"`
		PK      json.RawMessage `json:"pk"`
		SK      json.RawMessage `json:"sk"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("ateniese: UnmarshalTagger: %w", err)
	}
	s, ok := suite.SuiteByID(w.SuiteID)
	if !ok {
		return nil, fmt.Errorf("ateniese: UnmarshalTagger: unknown suite %d", w.SuiteID)
	}
	var pk pdp.PublicKey
	if err := json.Unmarshal(w.PK, &pk); err != nil {
		return nil, fmt.Errorf("ateniese: UnmarshalTagger: pk: %w", err)
	}
	var sk pdpateniese.SecretKey
	if err := json.Unmarshal(w.SK, &sk); err != nil {
		return nil, fmt.Errorf("ateniese: UnmarshalTagger: sk: %w", err)
	}
	return lineAteniese.NewTagger(&pk, &sk, s), nil
}

// erwayMarshalTagger serializes an Erway Tagger's key (pk N,G only — no secret key in DPDP I).
func erwayMarshalTagger(t SetupTagger) ([]byte, error) {
	st, ok := t.(*lineErway.Tagger)
	if !ok {
		return nil, fmt.Errorf("erway: MarshalTagger: unexpected Tagger type %T", t)
	}
	pkData, err := json.Marshal(st.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("erway: MarshalTagger: %w", err)
	}
	type wire struct {
		SuiteID uint8           `json:"suite_id"`
		PK      json.RawMessage `json:"pk"`
	}
	return json.Marshal(wire{SuiteID: suite.SuiteV1.ID(), PK: pkData})
}

func erwayUnmarshalTagger(data []byte) (SetupTagger, error) {
	type wire struct {
		SuiteID uint8           `json:"suite_id"`
		PK      json.RawMessage `json:"pk"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("erway: UnmarshalTagger: %w", err)
	}
	s, ok := suite.SuiteByID(w.SuiteID)
	if !ok {
		return nil, fmt.Errorf("erway: UnmarshalTagger: unknown suite %d", w.SuiteID)
	}
	var pk pdp.PublicKey
	if err := json.Unmarshal(w.PK, &pk); err != nil {
		return nil, fmt.Errorf("erway: UnmarshalTagger: pk: %w", err)
	}
	return lineErway.NewTagger(&pk, s), nil
}

// bjoMarshalTagger serializes a BJO Tagger's full MasterKey (all sub-keys + Params).
func bjoMarshalTagger(t SetupTagger) ([]byte, error) {
	st, ok := t.(*lineBJO.Tagger)
	if !ok {
		return nil, fmt.Errorf("bjo: MarshalTagger: unexpected Tagger type %T", t)
	}
	key, err := json.Marshal(st.MasterKey())
	if err != nil {
		return nil, fmt.Errorf("bjo: MarshalTagger: %w", err)
	}
	return json.Marshal(taggerKeyWire{SuiteID: suite.SuiteV1.ID(), Key: key})
}

func bjoUnmarshalTagger(data []byte) (SetupTagger, error) {
	var w taggerKeyWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("bjo: UnmarshalTagger: %w", err)
	}
	s, ok := suite.SuiteByID(w.SuiteID)
	if !ok {
		return nil, fmt.Errorf("bjo: UnmarshalTagger: unknown suite %d", w.SuiteID)
	}
	var mk porbjo.MasterKey
	if err := json.Unmarshal(w.Key, &mk); err != nil {
		return nil, fmt.Errorf("bjo: UnmarshalTagger: %w", err)
	}
	return lineBJO.NewTagger(&mk, s), nil
}

// Schemes is the canonical list of all implemented storage-proof schemes.
var Schemes = []SchemeSpec{
	{
		Name: "Ateniese",
		Cap:  Cap{SparseBlocks: true},
		NewTagger: func() func(int, int, int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(keyBits, _, _, _ int) (SetupTagger, error) {
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
		ChalFactory:     lineAteniese.NewChallengerFactory(),
		ProvFactory:     lineAteniese.NewProverFactory(),
		MarshalTagger:   ateniesesMarshalTagger,
		UnmarshalTagger: ateniesesUnmarshalTagger,
	},
	{
		Name: "Erway",
		Cap:  Cap{SparseBlocks: false},
		NewTagger: func() func(int, int, int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[int]func() (SetupTagger, error){}
			return func(keyBits, _, _, _ int) (SetupTagger, error) {
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
		ChalFactory:     lineErway.NewChallengerFactory(),
		ProvFactory:     lineErway.NewProverFactory(suite.SuiteV1),
		MarshalTagger:   erwayMarshalTagger,
		UnmarshalTagger: erwayUnmarshalTagger,
	},
	{
		Name: "SW-Priv",
		Cap:  Cap{SparseBlocks: true, Extraction: true},
		NewTagger: func() func(int, int, int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[taggerCacheKey]func() (SetupTagger, error){}
			return func(_, chalSize, blockSize, sectorsPerBlock int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				key := taggerCacheKey{chalSize, blockSize, sectorsPerBlock}
				fn, ok := cache[key]
				if !ok {
					sectorBytes := ceilDiv(blockSize, sectorsPerBlock)
					p, err := swPForSectorBytes(sectorBytes)
					if err != nil {
						return nil, err
					}
					sk, err := porsw.KeyGen(&porsw.Params{S: sectorsPerBlock, L: chalSize, P: p})
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineSW.NewTagger(sk, suite.SuiteV1), nil
					}
					cache[key] = fn
				}
				return fn()
			}
		}(),
		ChalFactory:     lineSW.NewChallengerFactory(),
		ProvFactory:     lineSW.NewProverFactory(),
		MarshalTagger:   swPrivMarshalTagger,
		UnmarshalTagger: swPrivUnmarshalTagger,
	},
	{
		Name: "BJO",
		Cap:  Cap{SparseBlocks: false, Extraction: true},
		NewTagger: func() func(int, int, int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[taggerCacheKey]func() (SetupTagger, error){}
			return func(_, chalSize, blockSize, _ int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				key := taggerCacheKey{chalSize: chalSize, blockSize: blockSize}
				fn, ok := cache[key]
				if !ok {
					bjoP, err := bjoPForBlockSize(blockSize)
					if err != nil {
						return nil, err
					}
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
					cache[key] = fn
				}
				return fn()
			}
		}(),
		ChalFactory:     lineBJO.NewChallengerFactory(),
		ProvFactory:     lineBJO.NewProverFactory(suite.SuiteV1),
		MarshalTagger:   bjoMarshalTagger,
		UnmarshalTagger: bjoUnmarshalTagger,
	},
	{
		Name: "SW-Pub",
		Cap:  Cap{SparseBlocks: true, Extraction: true},
		NewTagger: func() func(int, int, int, int) (SetupTagger, error) {
			var mu sync.Mutex
			cache := map[taggerCacheKey]func() (SetupTagger, error){}
			return func(_, chalSize, blockSize, sectorsPerBlock int) (SetupTagger, error) {
				mu.Lock()
				defer mu.Unlock()
				key := taggerCacheKey{chalSize, blockSize, sectorsPerBlock}
				fn, ok := cache[key]
				if !ok {
					sectorBytes := ceilDiv(blockSize, sectorsPerBlock)
					if sectorBytes > MaxSWPubSectorBytes {
						return nil, fmt.Errorf(
							"capability: SW-Pub sector size %d bytes exceeds max %d (blockSize=%d, sectorsPerBlock=%d): increase sectorsPerBlock or shrink blockSize",
							sectorBytes, MaxSWPubSectorBytes, blockSize, sectorsPerBlock)
					}
					ps, err := porsw.NewPubScheme(sectorsPerBlock, chalSize)
					if err != nil {
						return nil, err
					}
					fn = func() (SetupTagger, error) {
						return lineSwPub.NewTagger(ps, suite.SuiteV1), nil
					}
					cache[key] = fn
				}
				return fn()
			}
		}(),
		ChalFactory:     lineSwPub.NewChallengerFactory(),
		ProvFactory:     lineSwPub.NewProverFactory(),
		MarshalTagger:   swPubMarshalTagger,
		UnmarshalTagger: swPubUnmarshalTagger,
	},
}
