package line_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	lineAteniese "github.com/pinionengineering/storage-proofs/line/ateniese"
	lineSW "github.com/pinionengineering/storage-proofs/line/sw"
	lineSwPub "github.com/pinionengineering/storage-proofs/line/swpub"
	pdpateniese "github.com/pinionengineering/storage-proofs/pdp/ateniese"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

// sparseSetupFn mirrors setupFn (adapters_test.go) but also returns the
// factory and the full dense tag list, so a test can drive the TagStore-based
// path (NewProverFromTagStore) instead of NewProver.
type sparseSetupFn func(store blocks.BlockStore) (line.Challenger, line.SparseProverFactory, []byte, []line.Tag, blocks.BlockStore, error)

func ateniesSparseSetup(store blocks.BlockStore) (line.Challenger, line.SparseProverFactory, []byte, []line.Tag, blocks.BlockStore, error) {
	pk, sk, err := pdpateniese.KeyGen(128)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	tagger := lineAteniese.NewTagger(pk, sk, suite.SuiteV1)
	tags, err := tagger.TagBlocks(store)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ps, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ch, err := lineAteniese.NewChallengerFactory().NewChallenger(cs, testC)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return ch, lineAteniese.NewProverFactory(), ps, tags, tagger.EncodedBlocks(), nil
}

func swPrivSparseSetup(store blocks.BlockStore) (line.Challenger, line.SparseProverFactory, []byte, []line.Tag, blocks.BlockStore, error) {
	sk, err := porsw.KeyGen(&porsw.Params{S: 4, P: swP})
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	tagger := lineSW.NewTagger(sk, suite.SuiteV1)
	tags, err := tagger.TagBlocks(store)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ps, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ch, err := lineSW.NewChallengerFactory().NewChallenger(cs, testC)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return ch, lineSW.NewProverFactory(), ps, tags, tagger.EncodedBlocks(), nil
}

func swPubSparseSetup(store blocks.BlockStore) (line.Challenger, line.SparseProverFactory, []byte, []line.Tag, blocks.BlockStore, error) {
	ps, err := porsw.NewPubScheme(4)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	tagger := lineSwPub.NewTagger(ps, suite.SuiteV1)
	tags, err := tagger.TagBlocks(store)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	psp, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ch, err := lineSwPub.NewChallengerFactory().NewChallenger(cs, testC)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return ch, lineSwPub.NewProverFactory(), psp, tags, tagger.EncodedBlocks(), nil
}

// TestSparseProverRoundTrip drives the NewProverFromTagStore path a real
// Prove-time caller would use: build a Prover from a TagStore up front, with
// no separate step to learn which indices a challenge will sample, and
// confirm (a) the resulting proof verifies exactly as the dense NewProver
// path does in TestAdapterRoundTrip, and (b) Prove only ever called Tag()
// for a bounded, non-empty subset of indices — never the whole file.
func TestSparseProverRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		setup sparseSetupFn
	}{
		{"Ateniese", ateniesSparseSetup},
		{"SW-Priv", swPrivSparseSetup},
		{"SW-Pub", swPubSparseSetup},
	}

	raw := make([][]byte, testN)
	for i := range raw {
		raw[i] = make([]byte, testBlkSz)
		rand.Read(raw[i]) //nolint:errcheck
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := blocks.NewMemStore(raw)
			ch, factory, setup, tags, encoded, err := tc.setup(store)
			if err != nil {
				t.Fatal(err)
			}

			chal, v, err := ch.Challenge(encoded.IDs())
			if err != nil {
				t.Fatal(err)
			}

			// A recording TagStore backed by the full dense tag list — this
			// is the interface's whole point: nothing upstream needs to
			// learn which indices a challenge samples ahead of time. Prove
			// alone decides which positions to call Tag() for, and this
			// records exactly which ones that was.
			rec := newRecordingTagStore(tags)
			pv, err := factory.NewProverFromTagStore(setup, rec)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := pv.Prove(chal, encoded)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := v.Verify(chal, proof)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("honest sparse-constructed proof did not verify")
			}

			// The whole reason for TagStore: Prove must have touched a
			// bounded, non-empty subset of indices (the challenge sample),
			// never every tag in the file.
			touched := rec.touched()
			if len(touched) == 0 || len(touched) > testC {
				t.Fatalf("Prove fetched %d distinct tag indices, want (0, %d]", len(touched), testC)
			}

			// A TagStore missing one of the indices Prove actually needs
			// must fail cleanly, not silently produce a wrong proof or
			// panic. Reuse the indices just learned from the honest round.
			missing := touched[0]
			incomplete := newRecordingTagStore(tags)
			incomplete.omit(missing)
			pv2, err := factory.NewProverFromTagStore(setup, incomplete)
			if err != nil {
				// Some adapters might reasonably reject at construction
				// time instead of at Prove time; either is acceptable.
				return
			}
			if _, err := pv2.Prove(chal, encoded); err == nil {
				t.Fatalf("expected an error proving with tag %d missing (a challenged index)", missing)
			}
		})
	}
}

// recordingTagStore wraps a dense tag list as a line.TagStore, recording
// every index Tag() was actually called for — lets a test assert that a
// Prove call only ever fetched the challenged subset, never the whole file.
type recordingTagStore struct {
	tags    []line.Tag
	omitted map[int]bool
	seen    map[int]bool
}

func newRecordingTagStore(tags []line.Tag) *recordingTagStore {
	return &recordingTagStore{tags: tags, omitted: map[int]bool{}, seen: map[int]bool{}}
}

// omit makes Tag(i) return an error for i, simulating a TagStore that's
// missing one of the tags a challenge needs.
func (r *recordingTagStore) omit(i int) { r.omitted[i] = true }

func (r *recordingTagStore) Tag(i int) (line.Tag, error) {
	r.seen[i] = true
	if r.omitted[i] {
		return nil, fmt.Errorf("recordingTagStore: index %d deliberately omitted", i)
	}
	if i < 0 || i >= len(r.tags) {
		return nil, fmt.Errorf("recordingTagStore: index %d out of range [0, %d)", i, len(r.tags))
	}
	return r.tags[i], nil
}

// touched returns every index Tag() was called for, so far.
func (r *recordingTagStore) touched() []int {
	out := make([]int, 0, len(r.seen))
	for i := range r.seen {
		out = append(out, i)
	}
	return out
}
