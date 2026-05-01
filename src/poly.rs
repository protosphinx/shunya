//! Univariate polynomials over a [`Field`] + radix-2 NTT.
//!
//! The Number Theoretic Transform is the workhorse of every modern SNARK:
//! polynomial multiplication via pointwise mul on evaluations, fast inversion
//! of Vandermonde-like systems, batch evaluation at a coset. Once you have
//! a primitive `n`-th root of unity `ω` with `n` a power of two, the FFT
//! algorithm transports verbatim - the only difference from the complex
//! case is that arithmetic happens mod `p`.
//!
//! Goldilocks admits NTTs up to size `2^32` because the multiplicative group
//! has 2-adicity 32. The two-adic generator below is the standard
//! Plonky2-derived value `7^((p - 1) / 2^32)`.
//!
//! Implementation: in-place iterative Cooley–Tukey, bit-reversed input,
//! decimation-in-time. Inverse NTT runs the same butterfly with the inverse
//! root, then scales by `n^(-1)`.

use crate::field::{Field, Goldilocks};

/// Two-adicity of the Goldilocks multiplicative group: `(p - 1)` is divisible
/// by `2^32`, so NTTs of every power-of-two size up to `2^32` are available.
pub const TWO_ADICITY: u32 = 32;

/// Primitive `2^32`-th root of unity in Goldilocks.
///
/// Derivation: `7` is a multiplicative generator of `Z/p`'s group; the
/// `2^32`-th root is `7^((p - 1) / 2^32)`. This crate uses the canonical
/// Plonky2 value, verified by a unit test below to satisfy `ω^(2^32) = 1`
/// and `ω^(2^31) = -1`.
pub const TWO_ADIC_GENERATOR: Goldilocks = Goldilocks::new(1_753_635_133_440_165_772);

/// A univariate polynomial in coefficient form.
///
/// `coeffs[i]` is the coefficient on `x^i`. The polynomial is the formal sum;
/// trailing zeros are allowed (and required for NTTs of fixed size).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial<F: Field> {
    pub coeffs: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    pub fn new(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }

    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Evaluate at `x` via Horner's rule: `O(n)` field operations.
    pub fn evaluate(&self, x: F) -> F {
        let mut acc = F::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc * x + *c;
        }
        acc
    }

    /// Index of the highest non-zero coefficient. Returns `0` for the zero
    /// polynomial as a convenience (caller should treat that as a special case).
    pub fn degree(&self) -> usize {
        self.coeffs
            .iter()
            .rposition(|c| *c != F::ZERO)
            .unwrap_or(0)
    }

    /// Schoolbook multiplication: `O(n · m)`. Reference for testing the NTT
    /// path; production callers should pad and `ntt`-multiply for large `n`.
    pub fn naive_mul(&self, other: &Self) -> Self {
        if self.coeffs.is_empty() || other.coeffs.is_empty() {
            return Self::new(vec![]);
        }
        let n = self.coeffs.len() + other.coeffs.len() - 1;
        let mut out = vec![F::ZERO; n];
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                out[i + j] = out[i + j] + *a * *b;
            }
        }
        Self::new(out)
    }
}

/// Forward radix-2 NTT, in place. `coeffs.len()` must be a power of two and
/// no larger than `2^32`.
pub fn ntt(coeffs: &mut [Goldilocks]) {
    butterfly(coeffs, false);
}

/// Inverse NTT. Composes with [`ntt`] to the identity.
pub fn intt(coeffs: &mut [Goldilocks]) {
    butterfly(coeffs, true);
    let n_inv = Goldilocks::new(coeffs.len() as u64)
        .inv()
        .expect("NTT size must be coprime to p - it is, since size is a power of 2 ≤ 2^32");
    for c in coeffs.iter_mut() {
        *c *= n_inv;
    }
}

fn butterfly(coeffs: &mut [Goldilocks], inverse: bool) {
    let n = coeffs.len();
    assert!(
        n.is_power_of_two(),
        "NTT size must be a power of two, got {}",
        n
    );
    let log_n = n.trailing_zeros();
    assert!(
        log_n <= TWO_ADICITY,
        "NTT size 2^{} exceeds Goldilocks two-adicity 2^{}",
        log_n,
        TWO_ADICITY
    );

    bit_reverse(coeffs);

    // Primitive n-th root of unity.
    let mut omega_n = TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - log_n));
    if inverse {
        omega_n = omega_n.inv().expect("ω is non-zero");
    }

    // Iterative Cooley–Tukey.
    let mut len = 2usize;
    while len <= n {
        let half = len / 2;
        // ω for this stage: an `len`-th root of unity.
        let omega_step = omega_n.pow((n / len) as u64);
        let mut chunk = 0;
        while chunk < n {
            let mut w = Goldilocks::ONE;
            for j in 0..half {
                let u = coeffs[chunk + j];
                let v = coeffs[chunk + j + half] * w;
                coeffs[chunk + j] = u + v;
                coeffs[chunk + j + half] = u - v;
                w *= omega_step;
            }
            chunk += len;
        }
        len *= 2;
    }
}

fn bit_reverse<T>(arr: &mut [T]) {
    let n = arr.len() as u32;
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (32 - log_n);
        if i < j {
            arr.swap(i as usize, j as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::P;

    #[test]
    fn two_adic_generator_has_order_2_to_32() {
        let g = TWO_ADIC_GENERATOR;
        // g^(2^32) = 1
        assert_eq!(g.pow(1u64 << 32), Goldilocks::ONE);
        // g^(2^31) = -1
        assert_eq!(g.pow(1u64 << 31), Goldilocks::new(P - 1));
    }

    #[test]
    fn ntt_of_kronecker_delta_is_all_ones() {
        // x = [1, 0, 0, ..., 0] → X_k = Σ x_j ω^(jk) = 1 for all k.
        let mut a = vec![Goldilocks::ZERO; 8];
        a[0] = Goldilocks::ONE;
        ntt(&mut a);
        for v in &a {
            assert_eq!(*v, Goldilocks::ONE);
        }
    }

    #[test]
    fn ntt_then_intt_round_trips() {
        for log_n in 1..=10u32 {
            let n = 1usize << log_n;
            let mut a: Vec<Goldilocks> =
                (0..n).map(|i| Goldilocks::new(i as u64 + 1)).collect();
            let original = a.clone();
            ntt(&mut a);
            intt(&mut a);
            assert_eq!(a, original, "round-trip failed at n = {}", n);
        }
    }

    #[test]
    fn ntt_convolution_matches_naive() {
        // a = 1 + 2x + 3x^2;  b = 4 + 5x.  a·b = 4 + 13x + 22x^2 + 15x^3.
        let a = Polynomial::new(vec![
            Goldilocks::new(1),
            Goldilocks::new(2),
            Goldilocks::new(3),
        ]);
        let b = Polynomial::new(vec![Goldilocks::new(4), Goldilocks::new(5)]);
        let expected = a.naive_mul(&b);

        // Pad to next power of two ≥ deg(a) + deg(b) + 1 = 4. Use 8 for slack.
        let n = 8;
        let mut ae = vec![Goldilocks::ZERO; n];
        let mut be = vec![Goldilocks::ZERO; n];
        ae[..a.coeffs.len()].copy_from_slice(&a.coeffs);
        be[..b.coeffs.len()].copy_from_slice(&b.coeffs);

        ntt(&mut ae);
        ntt(&mut be);
        for i in 0..n {
            ae[i] *= be[i];
        }
        intt(&mut ae);

        for (i, c) in expected.coeffs.iter().enumerate() {
            assert_eq!(ae[i], *c, "coefficient {} mismatch", i);
        }
        // Any extra slots are zero.
        for v in &ae[expected.coeffs.len()..n] {
            assert_eq!(*v, Goldilocks::ZERO);
        }
    }

    #[test]
    fn ntt_of_size_one_is_identity() {
        let mut a = vec![Goldilocks::new(42)];
        ntt(&mut a);
        assert_eq!(a, vec![Goldilocks::new(42)]);
    }

    #[test]
    fn evaluate_via_horner() {
        // p(x) = 1 + 2x + 3x^2;  p(5) = 1 + 10 + 75 = 86.
        let p = Polynomial::new(vec![
            Goldilocks::new(1),
            Goldilocks::new(2),
            Goldilocks::new(3),
        ]);
        assert_eq!(p.evaluate(Goldilocks::new(5)), Goldilocks::new(86));
    }

    #[test]
    fn larger_ntt_convolution() {
        // Random-ish convolution at n = 64.
        let n = 64usize;
        let half = n / 2;
        let a_coeffs: Vec<_> = (0..half)
            .map(|i| Goldilocks::new((i as u64 * 31 + 7) % 1000))
            .collect();
        let b_coeffs: Vec<_> = (0..half)
            .map(|i| Goldilocks::new((i as u64 * 17 + 3) % 1000))
            .collect();
        let a = Polynomial::new(a_coeffs.clone());
        let b = Polynomial::new(b_coeffs.clone());
        let expected = a.naive_mul(&b);

        let mut ae = vec![Goldilocks::ZERO; n];
        let mut be = vec![Goldilocks::ZERO; n];
        ae[..half].copy_from_slice(&a_coeffs);
        be[..half].copy_from_slice(&b_coeffs);
        ntt(&mut ae);
        ntt(&mut be);
        for i in 0..n {
            ae[i] *= be[i];
        }
        intt(&mut ae);

        for (i, c) in expected.coeffs.iter().enumerate() {
            assert_eq!(ae[i], *c, "coefficient {} mismatch at n = {}", i, n);
        }
    }
}
