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
use crate::merkle::{merkle_verify, MerkleOpening, MerkleTree};
use crate::poly::{ntt, TWO_ADICITY, TWO_ADIC_GENERATOR};
use crate::transcript::Transcript;

/// One FRI folding round.
///
/// **Input ordering is load-bearing.** `evals[i]` must be the value of the
/// polynomial at `omega^i` for `i` in `0..n`, in natural index order. The
/// pairing `(evals[i], evals[i + n/2])` is then exactly `(p(x), p(-x))`
/// because `omega^(n/2) = -1`. If you produced the evaluations via
/// [`crate::ntt`] over `n` coefficients, you are already in this order.
/// If you produced them by some other means (e.g. bit-reversed output),
/// reorder before calling.
///
/// `evals` must contain `n` evaluations on `{ omega^0, omega^1, ...,
/// omega^(n-1) }`, where `omega` is a primitive `n`-th root of unity.
/// `n` must be at least 2 and a power of two. Returns the `n / 2`
/// evaluations of the folded polynomial on the squared domain
/// `{ omega^0, omega^2, omega^4, ..., omega^(n-2) }`.
pub fn fri_fold(evals: &[Goldilocks], alpha: Goldilocks, omega: Goldilocks) -> Vec<Goldilocks> {
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
        x *= omega;
    }
    out
}

/// One layer's worth of query evidence: the value at the queried point and
/// at its negation, plus Merkle openings for both.
#[derive(Clone, Debug)]
pub struct FriQueryLayer {
    pub at_pos: Goldilocks,
    pub at_neg: Goldilocks,
    pub opening_pos: MerkleOpening,
    pub opening_neg: MerkleOpening,
}

/// One full query: a chain of `FriQueryLayer`s, one per folding layer.
#[derive(Clone, Debug)]
pub struct FriQuery {
    pub layers: Vec<FriQueryLayer>,
}

/// A FRI proof. The prover commits to layer evaluations via Merkle roots,
/// folds all the way down to a single field element (`final_value`), and
/// supplies one query chain per `n_queries` to the verifier.
#[derive(Clone, Debug)]
pub struct FriProof {
    pub layer_roots: Vec<u64>,
    pub final_value: Goldilocks,
    pub queries: Vec<FriQuery>,
}

/// Extended FRI proof for the eval-based API. Folding stops at a
/// configurable `final_layer_size` (>= 2); the verifier checks the final
/// layer is constant.
#[derive(Clone, Debug)]
pub struct FriProofExt {
    pub layer_roots: Vec<u64>,
    pub final_layer: Vec<Goldilocks>,
    pub queries: Vec<FriQuery>,
}

/// Build a FRI proof for a polynomial given by its `d` coefficients
/// (degree `< d`). The prover internally evaluates on a size-`2d` domain
/// (2x blowup), then folds `log2(2d)` times down to a single constant.
///
/// `d` must be a positive power of two. `n_queries` controls soundness.
pub fn fri_prove(
    poly_coeffs: &[Goldilocks],
    n_queries: usize,
    transcript: &mut Transcript,
) -> FriProof {
    let d = poly_coeffs.len();
    assert!(
        d.is_power_of_two() && d >= 1,
        "FRI prover requires power-of-two coeff length >= 1, got {}",
        d
    );
    let n = d * 2;

    let mut current = poly_coeffs.to_vec();
    current.resize(n, Goldilocks::ZERO);
    ntt(&mut current);

    let mut current_omega = TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - n.trailing_zeros()));

    let mut layer_evals: Vec<Vec<Goldilocks>> = Vec::new();
    let mut layer_trees: Vec<MerkleTree> = Vec::new();
    let mut layer_roots: Vec<u64> = Vec::new();
    let mut alphas: Vec<Goldilocks> = Vec::new();

    while current.len() > 1 {
        let tree = MerkleTree::new(&current);
        let root = tree.root();
        layer_roots.push(root);
        transcript.append(Goldilocks::new(root));
        let alpha = transcript.challenge();
        alphas.push(alpha);
        layer_evals.push(current.clone());
        layer_trees.push(tree);

        current = fri_fold(&current, alpha, current_omega);
        current_omega *= current_omega;
    }
    let final_value = current[0];

    let mut queries = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        let q_seed = transcript.challenge().raw();
        let q = (q_seed as usize) % (n / 2);

        let mut layers = Vec::with_capacity(layer_trees.len());
        let mut q_at = q;
        for (layer_idx, evals) in layer_evals.iter().enumerate() {
            let half = evals.len() / 2;
            let pos_idx = q_at % half;
            let neg_idx = pos_idx + half;
            let at_pos = evals[pos_idx];
            let at_neg = evals[neg_idx];
            let opening_pos = layer_trees[layer_idx].open(pos_idx);
            let opening_neg = layer_trees[layer_idx].open(neg_idx);
            layers.push(FriQueryLayer {
                at_pos,
                at_neg,
                opening_pos,
                opening_neg,
            });
            q_at = pos_idx;
        }
        queries.push(FriQuery { layers });
    }

    FriProof {
        layer_roots,
        final_value,
        queries,
    }
}

/// Verify a FRI proof for a polynomial of degree `< d` (must match the
/// prover's `coeffs.len()`). Returns `true` only if every Merkle opening
/// checks, every folding-identity check holds, and the final folded value
/// matches across all queries.
pub fn fri_verify(
    d: usize,
    n_queries: usize,
    proof: &FriProof,
    transcript: &mut Transcript,
) -> bool {
    if !d.is_power_of_two() || d == 0 {
        return false;
    }
    let n = d * 2;
    let n_layers = n.trailing_zeros() as usize;
    if proof.layer_roots.len() != n_layers || proof.queries.len() != n_queries {
        return false;
    }

    let mut alphas: Vec<Goldilocks> = Vec::with_capacity(n_layers);
    for &root in &proof.layer_roots {
        transcript.append(Goldilocks::new(root));
        alphas.push(transcript.challenge());
    }

    let two_inv = (Goldilocks::ONE + Goldilocks::ONE)
        .inv()
        .expect("2 is non-zero in Goldilocks");

    for query in &proof.queries {
        if query.layers.len() != n_layers {
            return false;
        }
        let q_seed = transcript.challenge().raw();
        let q = (q_seed as usize) % (n / 2);

        let mut q_at = q;
        let mut current_omega = TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - n.trailing_zeros()));
        let mut current_size = n;

        for (layer_idx, layer) in query.layers.iter().enumerate() {
            let half = current_size / 2;
            let pos_idx = q_at % half;
            let neg_idx = pos_idx + half;

            if !merkle_verify(
                proof.layer_roots[layer_idx],
                pos_idx,
                layer.at_pos,
                &layer.opening_pos,
            ) {
                return false;
            }
            if !merkle_verify(
                proof.layer_roots[layer_idx],
                neg_idx,
                layer.at_neg,
                &layer.opening_neg,
            ) {
                return false;
            }

            let x = current_omega.pow(pos_idx as u64);
            let x_inv = x.inv().expect("domain element is non-zero");
            let even = (layer.at_pos + layer.at_neg) * two_inv;
            let odd = (layer.at_pos - layer.at_neg) * two_inv * x_inv;
            let expected = even + alphas[layer_idx] * odd;

            if layer_idx + 1 < n_layers {
                let next = &query.layers[layer_idx + 1];
                let next_size = current_size / 2;
                let next_half = next_size / 2;
                let claimed = if pos_idx < next_half {
                    next.at_pos
                } else {
                    next.at_neg
                };
                if claimed != expected {
                    return false;
                }
            } else if proof.final_value != expected {
                return false;
            }

            q_at = pos_idx;
            current_omega *= current_omega;
            current_size = half;
        }
    }

    true
}

/// Eval-based FRI prover: takes the polynomial's evaluations on the size-`n`
/// initial domain directly, instead of coefficients. Folds until the layer
/// size reaches `final_layer_size` (which must be `>= 2`).
///
/// This API is what makes a real *low-degree test*: the verifier can
/// supply arbitrary evaluations, the prover honestly folds them, and the
/// verifier rejects if the final layer is not constant. For evaluations
/// of a low-degree polynomial, the final layer is constant by construction.
/// For random or adversarial evaluations, it is constant only with
/// negligible probability over the prover's challenge alphas.
pub fn fri_prove_evals(
    evals: Vec<Goldilocks>,
    final_layer_size: usize,
    n_queries: usize,
    transcript: &mut Transcript,
) -> FriProofExt {
    let n = evals.len();
    assert!(
        n.is_power_of_two() && n >= 2 * final_layer_size,
        "n={} must be power of two >= 2 * final_layer_size={}",
        n,
        final_layer_size
    );
    assert!(
        final_layer_size.is_power_of_two() && final_layer_size >= 2,
        "final_layer_size must be a power of two >= 2"
    );

    let mut current = evals;
    let mut current_omega = TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - n.trailing_zeros()));

    let mut layer_evals: Vec<Vec<Goldilocks>> = Vec::new();
    let mut layer_trees: Vec<MerkleTree> = Vec::new();
    let mut layer_roots: Vec<u64> = Vec::new();

    while current.len() > final_layer_size {
        let tree = MerkleTree::new(&current);
        let root = tree.root();
        layer_roots.push(root);
        transcript.append(Goldilocks::new(root));
        let alpha = transcript.challenge();
        layer_evals.push(current.clone());
        layer_trees.push(tree);

        current = fri_fold(&current, alpha, current_omega);
        current_omega *= current_omega;
    }
    let final_layer = current;

    let mut queries = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        let q_seed = transcript.challenge().raw();
        let q = (q_seed as usize) % (n / 2);

        let mut layers = Vec::with_capacity(layer_trees.len());
        let mut q_at = q;
        for (layer_idx, evals) in layer_evals.iter().enumerate() {
            let half = evals.len() / 2;
            let pos_idx = q_at % half;
            let neg_idx = pos_idx + half;
            layers.push(FriQueryLayer {
                at_pos: evals[pos_idx],
                at_neg: evals[neg_idx],
                opening_pos: layer_trees[layer_idx].open(pos_idx),
                opening_neg: layer_trees[layer_idx].open(neg_idx),
            });
            q_at = pos_idx;
        }
        queries.push(FriQuery { layers });
    }

    FriProofExt {
        layer_roots,
        final_layer,
        queries,
    }
}

/// Eval-based FRI verifier. Returns `true` only if every Merkle opening
/// checks, every folding-identity check holds at every query, the
/// expected fold from the last query layer matches a value in `final_layer`,
/// and `final_layer` is constant (all values equal).
pub fn fri_verify_evals(
    n: usize,
    final_layer_size: usize,
    n_queries: usize,
    proof: &FriProofExt,
    transcript: &mut Transcript,
) -> bool {
    if !n.is_power_of_two() || n < 2 * final_layer_size {
        return false;
    }
    if !final_layer_size.is_power_of_two() || final_layer_size < 2 {
        return false;
    }
    let n_layers = n.trailing_zeros() as usize - final_layer_size.trailing_zeros() as usize;
    if proof.layer_roots.len() != n_layers
        || proof.final_layer.len() != final_layer_size
        || proof.queries.len() != n_queries
    {
        return false;
    }

    let mut alphas: Vec<Goldilocks> = Vec::with_capacity(n_layers);
    for &root in &proof.layer_roots {
        transcript.append(Goldilocks::new(root));
        alphas.push(transcript.challenge());
    }

    let two_inv = (Goldilocks::ONE + Goldilocks::ONE)
        .inv()
        .expect("2 is non-zero in Goldilocks");

    for query in &proof.queries {
        if query.layers.len() != n_layers {
            return false;
        }
        let q_seed = transcript.challenge().raw();
        let q = (q_seed as usize) % (n / 2);

        let mut q_at = q;
        let mut current_omega = TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - n.trailing_zeros()));
        let mut current_size = n;

        for (layer_idx, layer) in query.layers.iter().enumerate() {
            let half = current_size / 2;
            let pos_idx = q_at % half;
            let neg_idx = pos_idx + half;

            if !merkle_verify(
                proof.layer_roots[layer_idx],
                pos_idx,
                layer.at_pos,
                &layer.opening_pos,
            ) {
                return false;
            }
            if !merkle_verify(
                proof.layer_roots[layer_idx],
                neg_idx,
                layer.at_neg,
                &layer.opening_neg,
            ) {
                return false;
            }

            let x = current_omega.pow(pos_idx as u64);
            let x_inv = x.inv().expect("domain element is non-zero");
            let even = (layer.at_pos + layer.at_neg) * two_inv;
            let odd = (layer.at_pos - layer.at_neg) * two_inv * x_inv;
            let expected = even + alphas[layer_idx] * odd;

            if layer_idx + 1 < n_layers {
                let next = &query.layers[layer_idx + 1];
                let next_size = current_size / 2;
                let next_half = next_size / 2;
                let claimed = if pos_idx < next_half {
                    next.at_pos
                } else {
                    next.at_neg
                };
                if claimed != expected {
                    return false;
                }
            } else {
                // Last query layer's fold lands at position pos_idx in the
                // final_layer. Check it matches.
                if proof.final_layer[pos_idx] != expected {
                    return false;
                }
            }

            q_at = pos_idx;
            current_omega *= current_omega;
            current_size = half;
        }
    }

    // The defining low-degree check: final layer must be constant.
    let first = proof.final_layer[0];
    proof.final_layer.iter().all(|v| *v == first)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ---- Full FRI prover/verifier tests ----

    #[test]
    fn fri_proves_and_verifies_low_degree_polynomial() {
        // Polynomial of degree < 4 (length 4), 2x blowup -> domain size 8.
        let coeffs: Vec<_> = (0..4u64).map(|i| g(i * 7 + 3)).collect();
        let mut tp = Transcript::new(b"fri-test");
        let proof = fri_prove(&coeffs, 4, &mut tp);

        let mut tv = Transcript::new(b"fri-test");
        assert!(fri_verify(4, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_handles_d_equal_16() {
        let coeffs: Vec<_> = (0..16u64).map(|i| g(i * i + 1)).collect();
        let mut tp = Transcript::new(b"fri-16");
        let proof = fri_prove(&coeffs, 4, &mut tp);
        // n = 32, n_layers = log2(32) = 5
        assert_eq!(proof.layer_roots.len(), 5);

        let mut tv = Transcript::new(b"fri-16");
        assert!(fri_verify(16, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_handles_d_equal_1_constant() {
        // Constant polynomial: coeffs = [c]. n = 2.
        let coeffs = vec![g(42)];
        let mut tp = Transcript::new(b"fri-1");
        let proof = fri_prove(&coeffs, 4, &mut tp);
        assert_eq!(proof.layer_roots.len(), 1);

        let mut tv = Transcript::new(b"fri-1");
        assert!(fri_verify(1, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_rejects_tampered_merkle_opening() {
        let coeffs: Vec<_> = (0..4u64).map(|i| g(i + 1)).collect();
        let mut tp = Transcript::new(b"tamper-merkle");
        let mut proof = fri_prove(&coeffs, 4, &mut tp);

        proof.queries[0].layers[0].opening_pos.siblings[0] =
            proof.queries[0].layers[0].opening_pos.siblings[0].wrapping_add(1);

        let mut tv = Transcript::new(b"tamper-merkle");
        assert!(!fri_verify(4, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_rejects_tampered_layer_value() {
        let coeffs: Vec<_> = (0..4u64).map(|i| g(i + 5)).collect();
        let mut tp = Transcript::new(b"tamper-value");
        let mut proof = fri_prove(&coeffs, 4, &mut tp);

        proof.queries[0].layers[0].at_pos += g(1);

        let mut tv = Transcript::new(b"tamper-value");
        assert!(!fri_verify(4, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_rejects_tampered_final_value() {
        let coeffs: Vec<_> = (0..4u64).map(|i| g(i + 5)).collect();
        let mut tp = Transcript::new(b"final-value");
        let mut proof = fri_prove(&coeffs, 4, &mut tp);

        proof.final_value += g(1);

        let mut tv = Transcript::new(b"final-value");
        assert!(!fri_verify(4, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_rejects_wrong_param_lengths() {
        let coeffs: Vec<_> = (0..4u64).map(g).collect();
        let mut tp = Transcript::new(b"wrong-params");
        let proof = fri_prove(&coeffs, 3, &mut tp);

        let mut tv = Transcript::new(b"wrong-params");
        assert!(!fri_verify(4, 4, &proof, &mut tv));
    }

    // ---- Eval-based FRI tests (v0.6) ----

    /// Evaluate a polynomial of degree < d on the size-n domain via NTT.
    fn evals_of_low_degree_poly(coeffs: Vec<Goldilocks>, n: usize) -> Vec<Goldilocks> {
        assert!(coeffs.len() <= n);
        let mut padded = coeffs;
        padded.resize(n, Goldilocks::ZERO);
        ntt(&mut padded);
        padded
    }

    #[test]
    fn fri_evals_accepts_low_degree_polynomial() {
        // Polynomial of degree < 4, evaluated on size-16 domain (4x blowup).
        let coeffs = vec![g(2), g(3), g(5), g(7)];
        let n = 16;
        let evals = evals_of_low_degree_poly(coeffs, n);

        let mut tp = Transcript::new(b"v0.6-low-deg");
        let proof = fri_prove_evals(evals, 2, 8, &mut tp);

        let mut tv = Transcript::new(b"v0.6-low-deg");
        assert!(fri_verify_evals(n, 2, 8, &proof, &mut tv));
    }

    #[test]
    fn fri_evals_rejects_random_evaluations() {
        // Construct evaluations from a NON-low-degree function: random.
        // With overwhelming probability over folding alphas, the final
        // layer is not constant.
        let n = 16;
        let evals: Vec<_> = (0..n as u64)
            .map(|i| g(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)))
            .collect();

        let mut tp = Transcript::new(b"v0.6-random");
        let proof = fri_prove_evals(evals, 2, 8, &mut tp);

        let mut tv = Transcript::new(b"v0.6-random");
        // Verifier should reject: either final layer is not constant, OR
        // some intermediate query lands inconsistently.
        assert!(!fri_verify_evals(n, 2, 8, &proof, &mut tv));
    }

    #[test]
    fn fri_evals_rejects_random_at_final_layer_size_4() {
        let n = 32;
        let evals: Vec<_> = (0..n as u64)
            .map(|i| g(i.wrapping_mul(0xBF58_476D_1CE4_E5B9).wrapping_add(7)))
            .collect();

        let mut tp = Transcript::new(b"v0.6-random-32");
        let proof = fri_prove_evals(evals, 4, 8, &mut tp);

        let mut tv = Transcript::new(b"v0.6-random-32");
        assert!(!fri_verify_evals(n, 4, 8, &proof, &mut tv));
    }

    #[test]
    fn fri_evals_accepts_constant_function() {
        // A constant polynomial: every eval is the same.
        let n = 8;
        let evals = vec![g(42); n];

        let mut tp = Transcript::new(b"v0.6-const");
        let proof = fri_prove_evals(evals, 2, 4, &mut tp);

        let mut tv = Transcript::new(b"v0.6-const");
        assert!(fri_verify_evals(n, 2, 4, &proof, &mut tv));
    }

    #[test]
    fn fri_evals_rejects_almost_low_degree_with_one_spike() {
        // Take low-degree evals and tamper one entry. With high probability
        // the verifier catches the inconsistency at one of its queries.
        let coeffs = vec![g(11), g(13)];
        let n = 16;
        let mut evals = evals_of_low_degree_poly(coeffs, n);
        // Inject a "spike" at one position - destroys low-degree structure.
        evals[5] += g(99);

        let mut tp = Transcript::new(b"v0.6-spike");
        let proof = fri_prove_evals(evals, 2, 16, &mut tp);

        let mut tv = Transcript::new(b"v0.6-spike");
        assert!(!fri_verify_evals(n, 2, 16, &proof, &mut tv));
    }
}
