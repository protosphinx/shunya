//! Merkle tree commitments over Goldilocks field elements.
//!
//! A Merkle tree is the canonical way to commit to a vector of values such
//! that any single value can be opened cheaply (logarithmic-size proof) and
//! verified against a small root commitment. Used everywhere in modern ZK:
//!
//! - **FRI** uses Merkle trees to commit to polynomial evaluations on a
//!   coset; the prover opens leaves at random query points and the verifier
//!   checks consistency.
//! - **STARKs** use Merkle trees over the trace and constraint polynomials.
//! - **Halo2** can use Merkle (IPA) commitments instead of KZG.
//!
//! v0.3 ships a textbook binary Merkle tree over power-of-two-many leaves.
//! Each internal node is `hash_pair(left, right)`; each leaf is
//! `hash_one(value)`. The opening for index `i` is the sibling at every
//! level from leaf to root.
//!
//! Constraint: the leaf count must be a positive power of two. Padding
//! short vectors to the next power of two with zeros is the caller's job;
//! v0.4 makes this automatic and adds a depth-aware variant for FRI's
//! folding rounds.

use crate::field::Goldilocks;
use crate::hash::{hash_one, hash_pair};

/// A binary Merkle tree over Goldilocks values.
pub struct MerkleTree {
    n_leaves: usize,
    /// Flat layered storage. `nodes[0..n_leaves]` is the leaf hash layer;
    /// `nodes[n_leaves..n_leaves + n_leaves/2]` is the next layer up; and
    /// so on, with the root at `nodes.last()`.
    nodes: Vec<u64>,
}

impl MerkleTree {
    pub fn new(values: &[Goldilocks]) -> Self {
        assert!(
            !values.is_empty() && values.len().is_power_of_two(),
            "MerkleTree requires a positive power-of-two number of leaves, got {}",
            values.len()
        );
        let n = values.len();
        let mut nodes = Vec::with_capacity(2 * n - 1);
        for v in values {
            nodes.push(hash_one(v.raw()));
        }
        let mut layer_start = 0;
        let mut layer_len = n;
        while layer_len > 1 {
            for i in 0..layer_len / 2 {
                let l = nodes[layer_start + 2 * i];
                let r = nodes[layer_start + 2 * i + 1];
                nodes.push(hash_pair(l, r));
            }
            layer_start += layer_len;
            layer_len /= 2;
        }
        Self {
            n_leaves: n,
            nodes,
        }
    }

    pub fn n_leaves(&self) -> usize {
        self.n_leaves
    }

    pub fn root(&self) -> u64 {
        *self.nodes.last().expect("non-empty tree")
    }

    /// Produce an opening for leaf `idx`. The opening contains the sibling
    /// hash at every level walking from leaf to root.
    pub fn open(&self, idx: usize) -> MerkleOpening {
        assert!(
            idx < self.n_leaves,
            "leaf index {} out of bounds for tree of {} leaves",
            idx,
            self.n_leaves
        );
        let mut siblings = Vec::new();
        let mut layer_start = 0;
        let mut layer_len = self.n_leaves;
        let mut i = idx;
        while layer_len > 1 {
            let sibling_idx = if i % 2 == 0 { i + 1 } else { i - 1 };
            siblings.push(self.nodes[layer_start + sibling_idx]);
            layer_start += layer_len;
            layer_len /= 2;
            i /= 2;
        }
        MerkleOpening { siblings }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleOpening {
    pub siblings: Vec<u64>,
}

/// Verify that `value` is the leaf at index `idx` in a tree with the given
/// `root`, using `opening.siblings` to recompute the path.
pub fn merkle_verify(
    root: u64,
    idx: usize,
    value: Goldilocks,
    opening: &MerkleOpening,
) -> bool {
    let mut current = hash_one(value.raw());
    let mut i = idx;
    for sibling in &opening.siblings {
        current = if i % 2 == 0 {
            hash_pair(current, *sibling)
        } else {
            hash_pair(*sibling, current)
        };
        i /= 2;
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    #[test]
    fn open_then_verify_works_for_every_leaf() {
        let values: Vec<_> = (0..16).map(|i| g(i * 31 + 7)).collect();
        let tree = MerkleTree::new(&values);
        let root = tree.root();
        for (idx, value) in values.iter().enumerate() {
            let opening = tree.open(idx);
            assert!(
                merkle_verify(root, idx, *value, &opening),
                "leaf {} should verify",
                idx
            );
        }
    }

    #[test]
    fn tampered_leaf_value_is_rejected() {
        let values: Vec<_> = (0..8).map(|i| g(i)).collect();
        let tree = MerkleTree::new(&values);
        let root = tree.root();
        let opening = tree.open(3);
        let tampered = g(values[3].raw() + 1);
        assert!(!merkle_verify(root, 3, tampered, &opening));
    }

    #[test]
    fn tampered_sibling_is_rejected() {
        let values: Vec<_> = (0..8).map(|i| g(i)).collect();
        let tree = MerkleTree::new(&values);
        let root = tree.root();
        let mut opening = tree.open(2);
        opening.siblings[0] = opening.siblings[0].wrapping_add(1);
        assert!(!merkle_verify(root, 2, values[2], &opening));
    }

    #[test]
    fn tampered_root_is_rejected() {
        let values: Vec<_> = (0..4).map(|i| g(i)).collect();
        let tree = MerkleTree::new(&values);
        let root = tree.root();
        let opening = tree.open(0);
        assert!(!merkle_verify(root.wrapping_add(1), 0, values[0], &opening));
    }

    #[test]
    fn wrong_index_is_rejected() {
        let values: Vec<_> = (0..8).map(|i| g(i * 13)).collect();
        let tree = MerkleTree::new(&values);
        let root = tree.root();
        let opening = tree.open(2);
        // Claim leaf 2's value lives at index 6 instead.
        assert!(!merkle_verify(root, 6, values[2], &opening));
    }

    #[test]
    fn single_leaf_tree_is_trivial_root() {
        let values = vec![g(42)];
        let tree = MerkleTree::new(&values);
        let opening = tree.open(0);
        assert_eq!(opening.siblings.len(), 0);
        assert!(merkle_verify(tree.root(), 0, values[0], &opening));
    }

    #[test]
    fn opening_size_is_log_of_leaves() {
        for log_n in 0..10u32 {
            let n = 1usize << log_n;
            let values: Vec<_> = (0..n).map(|i| g(i as u64)).collect();
            let tree = MerkleTree::new(&values);
            let opening = tree.open(0);
            assert_eq!(opening.siblings.len(), log_n as usize);
        }
    }
}
