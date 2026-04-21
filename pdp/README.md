# pdp — Scalable Provable Data Possession (S-PDP)

A Go implementation of the S-PDP protocol from:

> Ateniese et al., "Provable Data Possession at Untrusted Stores"  
> Full paper: `doc/provable-data-possession.pdf`

## What it does

S-PDP lets a client verify that a remote server is faithfully storing a file
without downloading the file. The client uploads the file and a set of
cryptographic tags, then later issues random challenges; the server responds
with an aggregated proof that can be verified in constant time regardless of
file size.

## Protocol overview

| Phase | Actor | Operation |
|---|---|---|
| Setup | Client | `KeyGen` → `TagBlock` × n → upload blocks + tags → delete local copies |
| Challenge | Client | Generate random `s`; build `Challenge{Gs: g^s, …}`; send to server |
| Proof | Server | `GenProof(pk, blocks, chal, tags)` → return proof |
| Verify | Client | `CheckProof(pk, sk, s, tags, chal, proof)` |

## Deviations from the paper

The implementation is faithful to the paper with the following deliberate
adaptations:

**Block encoding.** The paper treats block content `m` as a raw integer
exponent. This implementation SHA-256 hashes each block before use, which is
necessary for arbitrary-length byte slices. The same hash is applied in both
`TagBlock` and `GenProof`, so the verification equation is unaffected.

**Full-domain hash.** `hashToQRN` implements the paper's footnote-3 FDH
construction using MGF1 (RFC 8017 §B.2.1) with SHA-256. This produces a
near-uniform distribution over QR_N with bias < 2^{-128}, matching the
paper's uniformity requirement.

**PRF coefficient length.** The paper leaves the coefficient length ℓ as a
protocol parameter. This implementation uses ℓ = 128 bits (the first 16 bytes
of HMAC-SHA-256), which is standard and bounds the server-side exponent μ to
at most C×256 bits.

**Challenge blinding.** The challenge struct carries `Gs = g^s` (the public
blinding factor) rather than the raw secret `s`. The client keeps `s` private
and passes it directly to `CheckProof`. This matches the paper's intended
security model: the server never learns `s`.

## Security parameter

`KeyGen(k)` generates safe primes of `k` bits, giving an RSA modulus of ~2k
bits. The paper requires k ≥ 1024 for security. Smaller values (e.g. k = 128)
are only suitable for tests.