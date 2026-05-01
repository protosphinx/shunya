//! FRI folding (Ben-Sasson, Bentov, Horesh, Riabzev, 2018).
//!
//! FRI is a low-degree test: a prover convinces a verifier that a function
//! `f : D -> F` is close to a polynomial of degree below some bound. It is
//! the polynomial commitment scheme behind STARKs and the recursion-friendly
//! variant of Halo2.
//!
//! The core operation is **folding**. Given evaluations of a polynomial
//! `p(x)` of degree `< n` on a multiplicative subgroup
//! `D = { omega^0, omega^1, ..., omega^(n-1) }` and a random challenge
//! `alpha`, the prover produces evaluations of
//!
//! ```text
//! p'(y) = p_even(y) + alpha · p_odd(y)
//! ```
//!
//! on the squared domain `D' = D^2`, which has half the size and is itself
//! a multiplicative subgroup with generator `omega^2`. The folded polynomial
//! has degree below `n / 2`.
//!
//! Repeating the fold `log2(n)` times reduces the claim to "the final
//! polynomial is a constant." A full FRI proof system surrounds these folds
//! with Merkle commitments and a query phase; v0.4 ships the folding
//! primitive in isolation, validated against the polynomial identity.
//!
//! # Folding identity
//!
//! For any `x` in the domain, `x_{i + n/2} = -x_i` because `omega^{n/2} = -1`.
//! Splitting `p` into even and odd parts:
//!
//! ```text
//! p(x)  = p_even(x^2) + x · p_odd(x^2)
//! p(-x) = p_even(x^2) - x · p_odd(x^2)
//! ```
//!
//! Solving:
//!
//! ```text
//! p_even(x^2) = (p(x) + p(-x)) / 2
//! p_odd(x^2)  = (p(x) - p(-x)) / (2 x)
//! ```
//!
//! And the folded value at `x^2`:
//!
//! ```text
//! p'(x^2) = p_even(x^2) + alpha · p_odd(x^2)
//!         = (p(x) + p(-x)) / 2 + alpha · (p(x) - p(-x)) / (2 x)
//! ```

use crate::field::{Field, Goldilocks};

/// One FRI folding round.
///
/// `evals` must contain `n` evaluations of a polynomial on the domain
/// `{ omega^0, omega^1, ..., omega^(n-1) }` in natural order, where `omega`
/// is a primitive `n`-th root of unity. `n` must be at least 2 and a power
/// of two. Returns the `n / 2` evaluations of the folded polynomial on the
/// squared domain.
pub fn fri_fold(
    evals: &[Goldilocks],
    alpha: Goldilocks,
    omega: Goldilocks,
) -> Vec<Goldilocks> {
    let n = evals.len();
    assert!(
        n >= 2 && n.is_power_of_two(),
        "FRI fold requires power-of-two length >= 2, got {}",
        n
    );
    let half = n / 2;
    let two_inv = (Goldilocks::ONE + Goldilocks::ONE)
        .inv()
        .expect("2 is non-zero in Goldilocks");
    let mut x = Goldilocks::ONE;
    let mut out = Vec::with_capacity(half);
    for i in 0..half {
        let f_pos = evals[i];
        let f_neg = evals[i + half];
        let x_inv = x.inv().expect("domain elements are non-zero");
        let even = (f_pos + f_neg) * two_inv;
        let odd = (f_pos - f_neg) * two_inv * x_inv;
        out.push(even + alpha * odd);
        x = x * omega;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::{ntt, TWO_ADICITY, TWO_ADIC_GENERATOR};

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    fn omega_n(n: usize) -> Goldilocks {
        TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - n.trailing_zeros()))
    }

    #[test]
    fn fold_matches_polynomial_identity_at_n_4() {
        // p(x) = 1 + 2x + 3x^2 + 4x^3. Even part: 1 + 3y. Odd part: 2 + 4y.
        let coeffs = vec![g(1), g(2), g(3), g(4)];
        let n = coeffs.len();
        let mut evals = coeffs.clone();
        ntt(&mut evals);

        let alpha = g(7);
        let omega = omega_n(n);
        let folded = fri_fold(&evals, alpha, omega);

        // p_folded(y) = (1 + alpha*2) + (3 + alpha*4) y. Evaluate on D^2.
        let mut p_folded_evals = vec![g(1) + alpha * g(2), g(3) + alpha * g(4)];
        ntt(&mut p_folded_evals);
        assert_eq!(folded, p_folded_evals);
    }

    #[test]
    fn fold_at_n_8_via_even_odd_decomposition() {
        let coeffs: Vec<_> = (0..8).map(|i| g(i * 13 + 5)).collect();
        let n = coeffs.len();
        let mut evals = coeffs.clone();
        ntt(&mut evals);

        let alpha = g(99);
        let omega = omega_n(n);
        let folded = fri_fold(&evals, alpha, omega);

        let p_folded_coeffs: Vec<_> = (0..4)
            .map(|i| coeffs[2 * i] + alpha * coeffs[2 * i + 1])
            .collect();
        let mut p_folded_evals = p_folded_coeffs;
        ntt(&mut p_folded_evals);
        assert_eq!(folded, p_folded_evals);
    }

    #[test]
    fn fold_iterated_to_constant_for_low_degree_input() {
        // p(x) = 1 + 2x (degree 1) padded to length 4.
        let coeffs = vec![g(1), g(2), g(0), g(0)];
        let n = 4;
        let mut evals = coeffs.clone();
        ntt(&mut evals);

        let alpha1 = g(11);
        let omega = omega_n(n);
        let folded1 = fri_fold(&evals, alpha1, omega);
        // p_even = 1, p_odd = 2. p'(y) = 1 + 11 * 2 = 23. Constant.
        assert_eq!(folded1.len(), 2);
        assert_eq!(folded1[0], g(23));
        assert_eq!(folded1[1], g(23));

        let alpha2 = g(17);
        let omega2 = omega * omega; // generator of size-2 domain
        let folded2 = fri_fold(&folded1, alpha2, omega2);
        // Even part of constant 23 is 23, odd part is 0. p''(y) = 23.
        assert_eq!(folded2.len(), 1);
        assert_eq!(folded2[0], g(23));
    }

    #[test]
    fn fold_at_n_16() {
        let coeffs: Vec<_> = (0..16).map(|i| g(i * i + 1)).collect();
        let n = coeffs.len();
        let mut evals = coeffs.clone();
        ntt(&mut evals);

        let alpha = g(31);
        let omega = omega_n(n);
        let folded = fri_fold(&evals, alpha, omega);

        let p_folded_coeffs: Vec<_> = (0..8)
            .map(|i| coeffs[2 * i] + alpha * coeffs[2 * i + 1])
            .collect();
        let mut p_folded_evals = p_folded_coeffs;
        ntt(&mut p_folded_evals);
        assert_eq!(folded, p_folded_evals);
    }

    #[test]
    fn fold_with_zero_alpha_recovers_even_part() {
        // alpha = 0 gives p_folded = p_even.
        let coeffs = vec![g(10), g(20), g(30), g(40)];
        let mut evals = coeffs.clone();
        ntt(&mut evals);
        let omega = omega_n(4);
        let folded = fri_fold(&evals, Goldilocks::ZERO, omega);

        let mut p_even_evals = vec![g(10), g(30)];
        ntt(&mut p_even_evals);
        assert_eq!(folded, p_even_evals);
    }
}
