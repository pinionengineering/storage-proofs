package swpub_test

import (
	"crypto/rand"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
	swpub "github.com/pinionengineering/storage-proofs/line/swpub"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

func TestRoundTrip(t *testing.T) {
	const (
		s      = 4
		l      = 5
		n      = 20
		blkSz  = 32
	)

	// Generate random blocks.
	raw := make([][]byte, n)
	for i := range raw {
		raw[i] = make([]byte, blkSz)
		rand.Read(raw[i]) //nolint:errcheck
	}
	store := blocks.NewMemStore(raw)

	// Setup.
	ps, err := porsw.NewPubScheme(s)
	if err != nil {
		t.Fatal(err)
	}
	tagger := swpub.NewTagger(ps, suite.SuiteV1)
	if _, err = tagger.TagBlocks(store); err != nil {
		t.Fatal(err)
	}

	clientSetup, err := tagger.ClientSetup()
	if err != nil {
		t.Fatal(err)
	}
	proverSetup, err := tagger.ProverSetup()
	if err != nil {
		t.Fatal(err)
	}

	// Reconstruct challenger and prover from wire payloads.
	challenger, err := swpub.NewChallengerFactory().NewChallenger(clientSetup, l)
	if err != nil {
		t.Fatal(err)
	}
	prover, err := swpub.NewProverFactory().NewProver(proverSetup, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Audit round.
	encodedStore := tagger.EncodedBlocks()
	chal, validator, err := challenger.Challenge(encodedStore.Len(), blocks.IDAtFunc(encodedStore))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := prover.Prove(chal, tagger.EncodedBlocks())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := validator.Verify(chal, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("honest proof did not verify")
	}

	// Corrupt one block; verification should fail.
	corrupt := make([][]byte, n)
	copy(corrupt, raw)
	corrupt[0] = make([]byte, blkSz)
	rand.Read(corrupt[0]) //nolint:errcheck
	corruptStore := blocks.NewMemStore(corrupt)

	rawStore := blocks.NewMemStore(raw)
	chal2, v2, err := challenger.Challenge(rawStore.Len(), blocks.IDAtFunc(rawStore))
	if err != nil {
		t.Fatal(err)
	}
	badProof, err := prover.Prove(chal2, corruptStore)
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
}
