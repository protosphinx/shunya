//! Multilinear polynomials over the boolean hypercube.
//!
//! A function `f : {0,1}^n → F` admits a unique *multilinear extension* (MLE)
//! `~f : F^n → F` that is multilinear in each variable and agrees with `f` on
//! the hypercube. The MLE is the one extension that doesn't introduce
//! spurious algebraic structure - exactly what sumcheck, lookup arguments,
//! and IVC consume as their input shape.
//!
//! Storage: the dense vector of evaluations on the hypercube, length `2^n`.
//! Indexing: little-endian. Index `i` corresponds to the binary digits
//! `(i & 1, (i >> 1) & 1, ..., (i >> (n-1)) & 1)`.
//!
//! Evaluation at an arbitrary `r ∈ F^n` uses the standard incremental fold:
//! fix `x_0 = r_0`, halving the array; then fix `x_1 = r_1`; etc. Each fold
//! is `O(2^k)` operations where `k` is the remaining variable count, so the
//! whole evaluation is `O(2^n)`.

use crate::field::Field;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultilinearPoly<F: Field> {
    pub evals: Vec<F>,
    pub n_vars: usize,
}

impl<F: Field> MultilinearPoly<F> {
    pub fn new(evals: Vec<F>) -> Self {
        assert!(
            evals.len().is_power_of_two(),
            "multilinear evaluation table must have power-of-two length, got {}",
            evals.len()
        );
        let n_vars = evals.len().trailing_zeros() as usize;
        Self { evals, n_vars }
    }

    /// Evaluate the multilinear extension at `r ∈ F^n`.
    pub fn evaluate(&self, r: &[F]) -> F {
        assert_eq!(
            r.len(),
            self.n_vars,
            "expected {} challenges, got {}",
            self.n_vars,
            r.len()
        );
        let mut current = self.evals.clone();
        for &ri in r {
            current = fold_first_var(&current, ri);
        }
        current[0]
    }

    /// Sum of `evals` over the hypercube - the "claim" that sumcheck attests.
    pub fn sum_over_hypercube(&self) -> F {
        let mut s = F::ZERO;
        for &v in &self.evals {
            s = s + v;
        }
        s
    }
}

/// Fold the first variable: produce the array `g(b_1, ..., b_{n-1}) =
/// (1 - r) f(0, b_1, ..., b_{n-1}) + r f(1, b_1, ..., b_{n-1})`.
///
/// Little-endian: index `2k` corresponds to `b_0 = 0` and index `2k + 1` to
/// `b_0 = 1` (after grouping pairs).
pub(crate) fn fold_first_var<F: Field>(evals: &[F], r: F) -> Vec<F> {
    let half = evals.len() / 2;
    let mut next = Vec::with_capacity(half);
    for k in 0..half {
        let a = evals[2 * k];
        let b = evals[2 * k + 1];
        next.push(a + r * (b - a));
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Goldilocks;

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    #[test]
    fn evaluation_on_hypercube_recovers_table() {
        // f(b0, b1) with table indexed (b0 + 2 b1).
        let table = vec![g(7), g(11), g(13), g(17)];
        let mle = MultilinearPoly::new(table.clone());
        // (b0=0, b1=0) → idx 0 → 7
        assert_eq!(mle.evaluate(&[g(0), g(0)]), g(7));
        // (b0=1, b1=0) → idx 1 → 11
        assert_eq!(mle.evaluate(&[g(1), g(0)]), g(11));
        // (b0=0, b1=1) → idx 2 → 13
        assert_eq!(mle.evaluate(&[g(0), g(1)]), g(13));
        // (b0=1, b1=1) → idx 3 → 17
        assert_eq!(mle.evaluate(&[g(1), g(1)]), g(17));
    }

    #[test]
    fn evaluation_at_arbitrary_point_matches_sum_of_eq_basis() {
        // For 2 vars: ~f(r0, r1) = (1-r0)(1-r1) f00 + r0(1-r1) f10
        //                       + (1-r0) r1   f01 + r0 r1   f11.
        let table = [g(7), g(11), g(13), g(17)];
        let mle = MultilinearPoly::new(table.to_vec());

        let r0 = g(3);
        let r1 = g(5);
        let one = Goldilocks::ONE;
        let expected = (one - r0) * (one - r1) * table[0]
            + r0 * (one - r1) * table[1]
            + (one - r0) * r1 * table[2]
            + r0 * r1 * table[3];
        assert_eq!(mle.evaluate(&[r0, r1]), expected);
    }

    #[test]
    fn sum_over_hypercube_is_just_table_sum() {
        let mle = MultilinearPoly::new(vec![g(2), g(3), g(5), g(7), g(11), g(13), g(17), g(19)]);
        let expected = g(2 + 3 + 5 + 7 + 11 + 13 + 17 + 19);
        assert_eq!(mle.sum_over_hypercube(), expected);
    }
}
