# Audit scope

- Primary: `pdp/` (ateniese, erway) and `por/` (sw, bjo) — the actual PDP/POR
  protocol implementations. This is where fidelity to the source papers and
  low-level math correctness matter most.
- Secondary: `suite/` — the PRF, PRP, and hash primitives shared by `pdp/`
  and `por/`. Not paper-specified, but load-bearing: a weak or misused
  primitive here undermines the security argument of every scheme that
  imports it.
- Lower priority: `capability/`, `line/`, `blocks/`, and `confidence/` — a
  capability registry, a user-facing adapter layer, a block-storage
  abstraction, and post-hoc detection-probability helpers. All four sit on
  the high-level API surface rather than in the protocol core, but they are
  live dependencies of it (`blocks/` and `line/` are both imported into or
  by the core schemes), not dead or purely illustrative code. Review for
  correct wiring and correct math on their own terms (e.g. `confidence/`'s
  probability calculations), but treat any nontrivial *new* cryptographic
  primitive found here as a red flag, not expected complexity.
- Exclude: `cmd/` and the top-level `docs/` directory. These are
  benchmarking/demo tooling and a generated report site — neither is part
  of the API surface or affects protocol soundness.

# Focus

- In `pdp/` and `por/`: check every equation, exponentiation, and
  challenge/response step against the paper cited in that scheme's package
  doc comment. Each scheme's `.go` file states which paper and section it
  implements — follow that pointer, not just the References list below.
  Where the code documents a deliberate deviation from the paper (see
  `pdp/README.md`'s "Deviations from the paper" section), verify the
  deviation's own correctness argument, not just that it's documented.
- In `suite/`: the papers deliberately underspecify primitive choice (e.g.
  "a pseudorandom function," "a full-domain hash into QR_N") rather than
  naming one. Assess whether the current choices — HMAC-SHA256,
  AES-256-CTR, and BLAKE3 keyed hash for the PRF; MGF1-SHA256 / BLAKE3-XOF
  for hash-to-QR_N; sort-by-HMAC-SHA256 for the PRP — are sound and
  appropriately matched to each scheme, and whether an alternative (e.g. a
  BLS/pairing-based construction for schemes that could use algebraic tags
  instead of a generic PRF) would be preferable. This is a primitive-choice
  review, not a paper-fidelity check.
- In `capability/` and `line/`: flag incorrect adaptation (wrong parameter
  passed through an adapter, a capability flag claiming a guarantee the
  underlying scheme doesn't provide). One exception worth checking:
  `capability/capability.go` re-derives a couple of scheme parameters
  (`swPForSectorBytes`, `MaxSWPubSectorBytes`) that mirror internal math in
  `por/sw` — confirm these stay consistent with `por/sw` rather than
  silently drifting from it.
- In `blocks/`: this is imported directly into `pdp/` and `por/`, so a bug
  in how blocks are indexed, stored, or retrieved (e.g. off-by-one in block
  IDs, silent truncation) can corrupt every scheme that depends on it even
  though the package itself contains no cryptography.
- In `confidence/`: check the detection-probability math on its own
  terms — it isn't defined by any of the papers, so there's no reference
  equation to check it against, but an incorrect confidence calculation
  would misrepresent the actual guarantee a passing audit provides to a
  caller.

# References

- ateniese (S-PDP): `pdp/doc/provable-data-possession.pdf`
  (also duplicated at `pdp/ateniese/doc/provable-data-possession.pdf`)
- erway (DPDP I): `pdp/doc/dynamic-provable-data-possession.pdf`
- bjo (POR): `por/doc/proofs-of-retrievability.pdf`
- sw (Compact POR): `por/doc/compact-proofs-of-retrievability.pdf`
- Repository overview and directory-by-directory rationale: `README.md`
