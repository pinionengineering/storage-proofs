# line — User-Facing Storage Proof API

The `line` package is the recommended entry point for applications. It defines
a unified set of interfaces (`Tagger`, `Challenger`, `Prover`, `Validator`)
that every protocol in this repository satisfies, and provides sub-packages
that wire up each protocol to those interfaces.

Import path: `github.com/pinionengineering/storage-proofs/line`

---

## Concepts

**Tagger** — runs once at setup time. Walks the file block by block, computes
a cryptographic authentication tag per block, and produces two artifacts: a
`client_setup` blob you keep, and a `prover_setup` blob you send to the server.

**Challenger** — runs on the client side. Reconstructed from `client_setup`,
it generates opaque challenge bytes for each audit round. Each call to
`Challenge` also returns a one-time `Validator` bound to that round's secret
randomness, making concurrent audit rounds safe.

**Prover** — runs on the server side. Reconstructed from `prover_setup` and
the stored (possibly encoded) blocks, it receives a challenge and produces a
compact proof.

**Validator** — ephemeral, client side. Created by `Challenger.Challenge`,
it holds the secret for one round. Call `Verify(challenge, proof)` to check
the proof. Discard after use.

---

## Setup vs. Audit

**Setup** is one-time per file:

```go
// 1. Tag the blocks.
tagger := lineSwpub.NewTagger(suite.SuiteV1)
tags, err := tagger.TagBlocks(store)

// 2. Distribute setup material.
proverSetup, _ := tagger.ProverSetup()  // send to server
clientSetup, _ := tagger.ClientSetup()  // keep locally

// 3. Initialize roles.
prover, _     := lineSwpub.NewProverFactory().NewProver(proverSetup, store)
challenger, _ := lineSwpub.NewChallengerFactory().NewChallenger(clientSetup, 20)
```

**Audit** repeats as often as you like:

```go
for {
    chal, validator, _ := challenger.Challenge(store.IDs())

    proof, _ := prover.Prove(chal, store)           // network: send chal, receive proof

    ok, _ := validator.Verify(chal, proof)           // local: no network
    if !ok {
        log.Fatal("data integrity failure")
    }
    time.Sleep(10 * time.Second)
}
```

---

## Protocol Comparison

| Protocol | Type      | Client state | Proof size       | Challenges  | Public verify |
|----------|-----------|--------------|------------------|-------------|---------------|
| `ateniese` | PDP     | O(N) tags    | O(1)             | Unlimited   | No            |
| `erway`    | PDP+Updates | O(1) skip-list root | O(log N) | Unlimited | Yes          |
| `sw`       | POR     | O(1)         | O(S) field elems | Unlimited   | No            |
| `swpub`    | POR     | O(1)         | O(S) group elems | Unlimited   | Yes           |
| `bjo`      | POR     | O(1)         | O(1) per round   | Bounded (Q) | No            |

N = number of blocks. S = blocks sampled per challenge (`challenge_size`).

---

## Choosing a Protocol

**`swpub`** is the best default for most workloads:
- Public verifiable: any third party can issue challenges using only the public key.
- Works naturally with IPFS DAGs via the `ipfs-storage-proofs` adapter.
- BLS elliptic-curve operations are fast at equivalent security levels.

**`ateniese`** is the simplest to reason about. Use it when you want minimal
moving parts and do not need public verifiability.

**`erway`** is the right choice when you need provably-correct support for
dynamic block updates (inserts, modifications, deletions).

**`bjo`** trades a bounded challenge quota for an extractability guarantee. Use
it only if you specifically need the BJO security model.

---

## Sub-Packages

```
line/
├── ateniese/   S-PDP adapter
├── erway/      DPDP I adapter
├── sw/         Shacham-Waters private-key POR adapter
├── swpub/      Shacham-Waters public-key POR adapter
└── bjo/        BJO POR adapter
```

Each sub-package exports:
- `NewTagger(...)` — creates a `Tagger`
- `NewProverFactory()` — creates a `ProverFactory` (call `.NewProver(setup, store)`)
- `NewChallengerFactory()` — creates a `ChallengerFactory` (call `.NewChallenger(setup, c)`)

---

## Wire Format

Challenges, proofs, tags, and setup blobs are all opaque `[]byte`. Their
internal encoding is an implementation detail of each sub-package. Pass them
verbatim between roles; do not parse them directly.

---

## See Also

- [`ipfs-storage-proofs`](https://github.com/pinionengineering/ipfs-storage-proofs) — adapter for IPFS content-addressed DAGs
- [`cmd/linedemo`](../cmd/) — reference server/client implementation running the full audit loop
- [`confidence/`](../confidence/) — helper functions for computing detection probability from audit results
