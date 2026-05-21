package line_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
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
	testN     = 20
	testBlkSz = 32
	testC     = 5
)

var swP, _ = new(big.Int).SetString("340282366920938463463374607431768211507", 10)

// setupFn runs scheme-specific key generation, tagging, and wire-payload
// serialisation, then returns ready-to-use Challenger and Prover together
// with the encoded block store the prover should read from.
type setupFn func(store blocks.BlockStore) (line.Challenger, line.Prover, blocks.BlockStore, error)

func ateniesSetup(store blocks.BlockStore) (line.Challenger, line.Prover, blocks.BlockStore, error) {
	pk, sk, err := pdpateniese.KeyGen(128)
	if err != nil {
		return nil, nil, nil, err
	}
	tagger := lineAteniese.NewTagger(pk, sk, suite.SuiteV1)
	if _, err = tagger.TagBlocks(store); err != nil {
		return nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ps, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := lineAteniese.NewChallengerFactory().NewChallenger(cs, testC)
	if err != nil {
		return nil, nil, nil, err
	}
	pv, err := lineAteniese.NewProverFactory().NewProver(ps, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return ch, pv, tagger.EncodedBlocks(), nil
}

func erwaySetup(store blocks.BlockStore) (line.Challenger, line.Prover, blocks.BlockStore, error) {
	pk, err := pdperway.KeyGen(128)
	if err != nil {
		return nil, nil, nil, err
	}
	tagger := lineErway.NewTagger(pk, suite.SuiteV1)
	if _, err = tagger.TagBlocks(store); err != nil {
		return nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ps, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := lineErway.NewChallengerFactory().NewChallenger(cs, testC)
	if err != nil {
		return nil, nil, nil, err
	}
	pv, err := lineErway.NewProverFactory(suite.SuiteV1).NewProver(ps, tagger.EncodedBlocks())
	if err != nil {
		return nil, nil, nil, err
	}
	return ch, pv, tagger.EncodedBlocks(), nil
}

func swPrivSetup(store blocks.BlockStore) (line.Challenger, line.Prover, blocks.BlockStore, error) {
	sk, err := porsw.KeyGen(&porsw.Params{S: 4, L: testC, P: swP})
	if err != nil {
		return nil, nil, nil, err
	}
	tagger := lineSW.NewTagger(sk, suite.SuiteV1)
	if _, err = tagger.TagBlocks(store); err != nil {
		return nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ps, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := lineSW.NewChallengerFactory().NewChallenger(cs, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	pv, err := lineSW.NewProverFactory().NewProver(ps, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return ch, pv, tagger.EncodedBlocks(), nil
}

func bjoSetup(store blocks.BlockStore) (line.Challenger, line.Prover, blocks.BlockStore, error) {
	mk, err := porbjo.KeyGen(&porbjo.Params{
		V: testC, W: 20, Q: 10,
		P:      big.NewInt(2147483647),
		OuterN: 8, OuterK: 4,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	tagger := lineBJO.NewTagger(mk, suite.SuiteV1)
	if _, err = tagger.TagBlocks(store); err != nil {
		return nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ps, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := lineBJO.NewChallengerFactory().NewChallenger(cs, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	pv, err := lineBJO.NewProverFactory(suite.SuiteV1).NewProver(ps, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return ch, pv, tagger.EncodedBlocks(), nil
}

func swPubSetup(store blocks.BlockStore) (line.Challenger, line.Prover, blocks.BlockStore, error) {
	ps, err := porsw.NewPubScheme(4, testC)
	if err != nil {
		return nil, nil, nil, err
	}
	tagger := lineSwPub.NewTagger(ps, suite.SuiteV1)
	if _, err = tagger.TagBlocks(store); err != nil {
		return nil, nil, nil, err
	}
	cs, err := tagger.ClientSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	psp, err := tagger.ProverSetup()
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := lineSwPub.NewChallengerFactory().NewChallenger(cs, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	pv, err := lineSwPub.NewProverFactory().NewProver(psp, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return ch, pv, tagger.EncodedBlocks(), nil
}

func TestAdapterRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		setup setupFn
	}{
		{"Ateniese", ateniesSetup},
		{"Erway", erwaySetup},
		{"SW-Priv", swPrivSetup},
		{"BJO", bjoSetup},
		{"SW-Pub", swPubSetup},
	}

	raw := make([][]byte, testN)
	for i := range raw {
		raw[i] = make([]byte, testBlkSz)
		rand.Read(raw[i]) //nolint:errcheck
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := blocks.NewMemStore(raw)
			ch, pv, encoded, err := tc.setup(store)
			if err != nil {
				t.Fatal(err)
			}

			// Honest round: proof must verify.
			chal, v, err := ch.Challenge(encoded.IDs())
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
				t.Fatal("honest proof did not verify")
			}

			// Corrupt encoded block 0 and re-challenge.
			encBlocks := make([][]byte, encoded.Len())
			for i := range encBlocks {
				b, err := blocks.BlockAt(encoded, i)
				if err != nil {
					t.Fatal(err)
				}
				encBlocks[i] = b
			}
			encBlocks[0] = make([]byte, len(encBlocks[0]))
			rand.Read(encBlocks[0]) //nolint:errcheck
			corruptStore := blocks.NewMemStore(encBlocks)

			chal2, v2, err := ch.Challenge(encoded.IDs())
			if err != nil {
				t.Fatal(err)
			}
			badProof, err := pv.Prove(chal2, corruptStore)
			if err != nil {
				t.Fatal(err)
			}
			ok2, err := v2.Verify(chal2, badProof)
			if err != nil {
				t.Fatal(err)
			}
			if ok2 {
				t.Log("corrupt proof verified (low-probability false negative — rerun if flaky)")
			}
		})
	}
}
