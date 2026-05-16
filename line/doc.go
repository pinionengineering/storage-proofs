// Package line provides a client-server abstraction over storage-proof schemes.
// Each protocol is implemented in a sub-package (ateniese, erway, sw, bjo);
// this package defines the interfaces they all satisfy.
//
// # Concepts
//
// A storage proof lets a client verify that a server is honestly storing a
// file without downloading it. The protocol has two roles:
//
//   - The client holds secret key material, issues periodic challenges, and
//     verifies the server's responses.
//   - The server holds the (possibly encoded) file and responds with proofs.
//
// # Setup (one-time)
//
// Before auditing can begin, the client tags the file and distributes the
// resulting artifacts to both sides:
//
//  1. Create a Tagger for the chosen protocol and call TagBlocks:
//
//     tagger := lineAteniese.NewTagger(pk, sk, suite)
//     tagger.TagBlocks(store)
//
//  2. Send the prover setup to the server and initialize a Prover:
//
//     setup, _ := tagger.ProverSetup()
//     prover, _ := lineAteniese.NewProverFactory().NewProver(setup, store)
//
//  3. The client retains its own setup and builds a Challenger:
//
//     clientSetup, _ := tagger.ClientSetup()
//     challenger, _ := lineAteniese.NewChallengerFactory().NewChallenger(clientSetup, c)
//
// For protocols that transform the file before storage (BJO encodes blocks
// with SA-ECC), the server stores tagger.EncodedBlocks() rather than the
// original file. For all other protocols, EncodedBlocks returns the same
// store passed to TagBlocks.
//
// # Auditing (repeated)
//
// Each audit round is three steps:
//
//  1. The client issues a challenge. Challenge also returns a Validator bound
//     to this round's secret, so concurrent rounds are safe:
//
//     chal, validator, _ := challenger.Challenge(numBlocks)
//
//  2. The client sends the challenge to the server, which responds:
//
//     proof, _ := prover.Prove(chal, store)
//
//  3. The client verifies the proof:
//
//     ok, _ := validator.Verify(chal, proof)
//
// # Protocols
//
// Four protocols are available, each as a sub-package:
//
//   - ateniese: S-PDP (Ateniese et al. 2007). The client holds O(N) state
//     (one tag per block). Each challenge covers a random subset of blocks.
//     Stateless server; no dynamic-update support.
//
//   - erway: DPDP I (Erway et al. 2009). The client holds O(1) state (the
//     root of an authenticated skip list). The server maintains the full skip
//     list. Supports provably-correct dynamic block updates.
//
//   - sw: Shacham-Waters private-key POR (2008). Extractable: a client that
//     receives enough honest proofs can recover the file. The number of blocks
//     challenged per round is fixed at key-generation time.
//
//   - bjo: BJO POR (Bowers-Juels-Oprea 2009). Challenges are pre-computed
//     sentinel ciphertexts issued sequentially up to a bound Q set at setup.
//     Extractable. Encodes the file with SA-ECC before storage.
//
// # Wire format
//
// Challenges, proofs, tags, and setup blobs are opaque []byte values. Their
// internal encoding is an implementation detail of each sub-package and may
// change between versions. Pass them verbatim between protocol roles; do not
// parse them directly.
package line
