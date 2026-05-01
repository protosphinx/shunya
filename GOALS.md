# GOALS — shunya

Higher-level intent than `README.md`. Sequenced milestones to a working PLONK-style prover.

## v0.0 — Goldilocks substrate ✦ **shipped**

- Prime field over `p = 2^64 - 2^32 + 1`
- `add`, `sub`, `neg`, `mul`, `pow`, `inv` (Fermat), `square`
- Tests: closure under each op, distributivity, Fermat's little theorem

## v0.1 — fast reduction + polynomials

- Replace `% P` with the limb-decomposition reduction exploiting `2^64 ≡ 2^32 − 1 (mod p)`
- Univariate polynomial type over `Goldilocks`
- Radix-2 NTT (Cooley–Tukey) using a primitive `2^k`-th root of unity
- Inverse NTT via the standard scaling trick
- Bench: NTT of size 2^20 on a single thread

## v0.2 — sumcheck + multilinear

- Multilinear extension type
- Sumcheck protocol (interactive + Fiat–Shamir transcript)
- Used later as the engine for both lookup arguments and IVC

## v0.3 — KZG over BLS12-381

- BLS12-381 scalar + base field (importing a curve crate is acceptable here; `halo2curves` or hand-rolled if energy permits)
- Pairing
- Trusted-setup serialization
- KZG commit / open / verify

## v0.4 — PLONK arithmetization

- Constraint system: gate equations, copy constraints, permutation argument
- Witness assignment
- Round-by-round prover and verifier
- One end-to-end demo: prove knowledge of `x` such that `x^3 + x + 5 = y` for public `y`

## v0.5 — lookup + custom gates

- LogUp lookup argument
- Custom gate API (degree-bounded multivariate polynomial constraints)
- Range checks via lookup

## v0.6 — recursion

- Cycle of curves (Pasta-style: Pallas + Vesta)
- Halo2-style accumulation scheme
- Recursive verification of one shunya proof inside another

## Non-goals

- Production-grade constant-time guarantees (educational impl)
- Hardware-specific assembly paths
- Proof systems other than PLONKish (no Groth16, no STARKs)
