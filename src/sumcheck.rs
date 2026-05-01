//! Sumcheck protocol for multilinear polynomials.
//!
//! The sumcheck protocol (Lund, Fortnow, Karloff, Nisan, 1992) reduces the
//! claim that
//!
//! ```text
//!     H = Σ_{x ∈ {0,1}^n} f(x)
//! ```
//!
//! to a single evaluation of `f` at a random point `r ∈ F^n`. Round `i`:
//!
//! 1. Prover sends `g_i(X) = Σ_{x_{i+1}, ..., x_n}  f(r_1, ..., r_{i-1}, X, x_{i+1}, ..., x_n)`.
//! 2. Verifier checks `g_i(0) + g_i(1) = current_claim` and samples `r_i`.
//! 3. The new claim is `g_i(r_i)`.
//!
//! After `n` rounds, the verifier needs `f(r_1, ..., r_n)` to finish. For a
//! multilinear `f`, `g_i(X)` is degree-1, so the prover sends just two field
//! elements per round (`g_i(0)` and `g_i(1)`).
//!
//! This module ships the prover, the verifier, and a `SumcheckProof` value
//! you can move across the wire. The transcript carries the Fiat–Shamir
//! challenges so the protocol is non-interactive.

use crate::field::{Field, Goldilocks};
use crate::multilinear::{fold_first_var, MultilinearPoly};
use crate::transcript::Transcript;

/// One round's univariate polynomial. For multilinear `f`, this has degree 1
/// and is fully determined by its evaluations at 0 and 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundPoly {
    pub at_0: Goldilocks,
    pub at_1: Goldilocks,
}

impl RoundPoly {
    /// Evaluate the degree-1 polynomial `g(X) = (1 - X) g(0) + X g(1)` at `r`.
    pub fn evaluate(&self, r: Goldilocks) -> Goldilocks {
        self.at_0 + r * (self.at_1 - self.at_0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof {
    pub round_polys: Vec<RoundPoly>,
}

/// Prover. Returns `(proof, claimed_evaluation_point, claimed_evaluation_of_f)`.
/// The verifier reconstructs the same point and value to check consistency.
pub fn sumcheck_prove(
    poly: &MultilinearPoly<Goldilocks>,
    transcript: &mut Transcript,
) -> (SumcheckProof, Vec<Goldilocks>, Goldilocks) {
    let mut current = poly.evals.clone();
    let n = poly.n_vars;
    let mut round_polys = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    for _ in 0..n {
        let half = current.len() / 2;
        let mut at_0 = Goldilocks::ZERO;
        let mut at_1 = Goldilocks::ZERO;
        for k in 0..half {
            at_0 += current[2 * k];
            at_1 += current[2 * k + 1];
        }
        let g = RoundPoly { at_0, at_1 };

        transcript.append(at_0);
        transcript.append(at_1);
        let r = transcript.challenge();
        round_polys.push(g);
        challenges.push(r);

        current = fold_first_var(&current, r);
    }

    let final_value = current[0];
    (SumcheckProof { round_polys }, challenges, final_value)
}

/// Verifier. Returns `Some((evaluation_point, claimed_evaluation))` if the
/// proof's structural checks pass. The caller must independently verify that
/// `f(point) = claimed_evaluation` - typically via a polynomial commitment
/// opening (v0.3) or, for tests, a direct evaluation.
pub fn sumcheck_verify(
    claim: Goldilocks,
    n_vars: usize,
    proof: &SumcheckProof,
    transcript: &mut Transcript,
) -> Option<(Vec<Goldilocks>, Goldilocks)> {
    if proof.round_polys.len() != n_vars {
        return None;
    }
    let mut current_claim = claim;
    let mut challenges = Vec::with_capacity(n_vars);
    for g in &proof.round_polys {
        if g.at_0 + g.at_1 != current_claim {
            return None;
        }
        transcript.append(g.at_0);
        transcript.append(g.at_1);
        let r = transcript.challenge();
        current_claim = g.evaluate(r);
        challenges.push(r);
    }
    Some((challenges, current_claim))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    #[test]
    fn honest_prover_passes_verification_at_n_2() {
        let mle = MultilinearPoly::new(vec![g(7), g(11), g(13), g(17)]);
        let claim = mle.sum_over_hypercube();

        let mut tp = Transcript::new(b"test");
        let (proof, point_p, value_p) = sumcheck_prove(&mle, &mut tp);

        let mut tv = Transcript::new(b"test");
        let (point_v, value_v) =
            sumcheck_verify(claim, mle.n_vars, &proof, &mut tv).expect("verifier must accept");

        // Verifier reconstructs the same evaluation point as the prover.
        assert_eq!(point_p, point_v);
        // Final claim equals f(point) - checkable by direct evaluation here.
        let direct = mle.evaluate(&point_v);
        assert_eq!(value_v, direct);
        assert_eq!(value_p, direct);
    }

    #[test]
    fn honest_prover_passes_at_n_4() {
        let evals: Vec<_> = (0..16).map(|i| g(i as u64 * 31 + 17)).collect();
        let mle = MultilinearPoly::new(evals);
        let claim = mle.sum_over_hypercube();

        let mut tp = Transcript::new(b"test-n4");
        let (proof, _, value_p) = sumcheck_prove(&mle, &mut tp);

        let mut tv = Transcript::new(b"test-n4");
        let (point_v, value_v) =
            sumcheck_verify(claim, mle.n_vars, &proof, &mut tv).expect("verifier must accept");

        assert_eq!(value_v, mle.evaluate(&point_v));
        assert_eq!(value_p, value_v);
    }

    #[test]
    fn wrong_claim_fails_verification() {
        let mle = MultilinearPoly::new(vec![g(7), g(11), g(13), g(17)]);
        let mut tp = Transcript::new(b"test-bad");
        let (proof, _, _) = sumcheck_prove(&mle, &mut tp);

        // Verify against a wrong claim - should be rejected at round 1.
        let mut tv = Transcript::new(b"test-bad");
        let bad_claim = mle.sum_over_hypercube() + g(1);
        assert!(sumcheck_verify(bad_claim, mle.n_vars, &proof, &mut tv).is_none());
    }

    #[test]
    fn tampered_round_poly_fails_verification() {
        let mle = MultilinearPoly::new(vec![g(7), g(11), g(13), g(17)]);
        let claim = mle.sum_over_hypercube();
        let mut tp = Transcript::new(b"test-tamper");
        let (mut proof, _, _) = sumcheck_prove(&mle, &mut tp);

        // Flip the last round's at_1 - first-round consistency still holds,
        // but the chain breaks at the last step.
        let last = proof.round_polys.len() - 1;
        proof.round_polys[last].at_1 += g(1);

        let mut tv = Transcript::new(b"test-tamper");
        // Verifier follows the protocol and reconstructs an evaluation point.
        // The structural g(0)+g(1)=claim check passes for tampered round polys
        // unless they violate the running claim - ensure the final point
        // disagrees with the polynomial.
        let result = sumcheck_verify(claim, mle.n_vars, &proof, &mut tv);
        if let Some((point, value)) = result {
            // Even if the structural checks pass, the final value must
            // disagree with the polynomial's actual evaluation.
            assert_ne!(value, mle.evaluate(&point));
        }
        // (Otherwise verification rejected outright - also acceptable.)
    }

    #[test]
    fn proof_length_must_match_n_vars() {
        let mle = MultilinearPoly::new(vec![g(7), g(11), g(13), g(17)]);
        let claim = mle.sum_over_hypercube();
        let mut tp = Transcript::new(b"test-len");
        let (mut proof, _, _) = sumcheck_prove(&mle, &mut tp);
        proof.round_polys.pop();

        let mut tv = Transcript::new(b"test-len");
        assert!(sumcheck_verify(claim, mle.n_vars, &proof, &mut tv).is_none());
    }
}
