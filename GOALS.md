# GOALS - shunya

Higher-level intent than `README.md`. Sequenced milestones to a working PLONK-style prover.

## v0.0 - Goldilocks substrate ✦ **shipped**

- Prime field over `p = 2^64 - 2^32 + 1`
- `add`, `sub`, `neg`, `mul`, `pow`, `inv` (Fermat), `square`
- Tests: closure under each op, distributivity, Fermat's little theorem

## v0.1 - fast reduction + polynomials ✦ **shipped**

- Plonky2-style fast Goldilocks reduction; cross-tested against `% P`
- `Polynomial<F>` with Horner evaluation, naive multiplication
- Radix-2 NTT and inverse NTT, in-place, iterative Cooley–Tukey
- Validated two-adic generator: `ω^(2^32) = 1`, `ω^(2^31) = -1`
- Tests: round-trip at sizes 2..2^10, NTT-based convolution matches naive at n = 8 and n = 64

## v0.2 - sumcheck + multilinear

- Multilinear extension type
- Sumcheck protocol (interactive + Fiat–Shamir transcript)
- Used later as the engine for both lookup arguments and IVC

## v0.3 - Merkle tree commitments ✦ **shipped**

- Pivoted from KZG to FRI/STARK substrate (Goldilocks-native, no pairings)
- `hash::{hash_one, hash_pair}`: toy FNV+rotation hash (cryptographically not
  secure; v0.5 swaps in a real hash). Domain-separated for unary vs pair.
- `MerkleTree::new` over a power-of-two Goldilocks vector; `root`, `open(idx)`
- `merkle_verify(root, idx, value, opening)`
- Tests: every leaf opens-and-verifies in 16-leaf tree, tampered leaf
  rejected, tampered sibling rejected, tampered root rejected, wrong index
  rejected, single-leaf trivial root, opening size = log2(n)

## v0.4 - FRI low-degree test

- Build the FRI folding round-by-round on top of the Merkle layer
- Prover: commit to `f`, fold to `f'` of half degree, repeat to constant
- Verifier: query random points, check consistency of folded values
- One end-to-end demo: prove a polynomial has degree below the bound

## v0.5 - real hash + KZG variant

- Swap toy hash for BLAKE3 (off-chain) or Poseidon (recursion-friendly)
- Optional KZG track: BLS12-381 scalar + base field (importing a curve crate
  is acceptable here; `halo2curves` or hand-rolled if energy permits),
  pairing, KZG commit / open / verify

## v0.6 - PLONK arithmetization

- Constraint system: gate equations, copy constraints, permutation argument
- Witness assignment
- Round-by-round prover and verifier
- One end-to-end demo: prove knowledge of `x` such that `x^3 + x + 5 = y` for public `y`

## v0.7 - lookup + custom gates

- LogUp lookup argument
- Custom gate API (degree-bounded multivariate polynomial constraints)
- Range checks via lookup

## v0.8 - recursion

- Cycle of curves (Pasta-style: Pallas + Vesta)
- Halo2-style accumulation scheme
- Recursive verification of one shunya proof inside another

## Non-goals

- Production-grade constant-time guarantees (educational impl)
- Hardware-specific assembly paths
- Proof systems other than PLONKish (no Groth16, no STARKs)
