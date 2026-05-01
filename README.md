<h1 align="center">shunya</h1>

<p align="center"><em>शून्य — Sanskrit gave the world <strong>zero</strong>. This gives the world <strong>zero-knowledge</strong>.</em></p>

---

A from-scratch zero-knowledge proving system in Rust. No `arkworks`, no `halo2`, no `bellman` — every primitive built up from the field arithmetic on the way to a working PLONKish prover.

## Why from scratch

The existing ZK stacks are excellent and you should use them in production. This repo is the opposite of production — it exists because *building it ourselves is the point*. Every layer is a chance to understand a piece of cryptography that is otherwise a black box behind 30k lines of someone else's macros.

## Roadmap

The path to a working proof is paved. We walk it once, deliberately:

| v   | Layer | Status |
|-----|-------|--------|
| 0.0 | Goldilocks prime field — add/sub/mul/neg/pow/inv | **shipped** |
| 0.1 | Univariate polynomials + radix-2 NTT | next |
| 0.2 | Multilinear polynomials + sumcheck | |
| 0.3 | KZG commitment over BLS12-381 | |
| 0.4 | PLONK arithmetization, copy constraints | |
| 0.5 | Custom gates, lookup arguments (LogUp) | |
| 0.6 | Halo2-style accumulation + recursion | |

## Why Goldilocks first

`p = 2^64 - 2^32 + 1`. Three things make it the right starting field:

1. **Cheap reduction.** `2^64 ≡ 2^32 − 1 (mod p)`, so a 128-bit product collapses to a few `u64` ops. (v0 punts on the fast path and uses a straight `% P`; v0.1 lands the limb decomposition.)
2. **NTT-friendliness.** The multiplicative group has order `2^32 · 3 · 5 · 17 · 257 · 65537`. Power-of-two FFTs of every size up to 2^32 are available — exactly what a polynomial commitment scheme wants.
3. **Small-field arithmetic.** Fits in a single `u64`; vectorizes well; lets us defer the bignum machinery until pairings show up at v0.3.

Used in production by Plonky2, Starks, RISC Zero — well-trodden ground.

## Use

```toml
[dependencies]
shunya = "0.0.1"
```

```rust
use shunya::Goldilocks;
use shunya::field::Field;

let a = Goldilocks::new(7);
let b = Goldilocks::new(13);
assert_eq!(a * b, Goldilocks::new(91));

let inv = a.inv().unwrap();
assert_eq!(a * inv, Goldilocks::ONE);
```

## License

MIT.

---

<p align="center"><a href="https://x.com/protosphinx">@protosphinx</a></p>
