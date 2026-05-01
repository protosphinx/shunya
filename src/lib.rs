//! shunya - Sanskrit gave the world *zero*; this gives the world *zero-knowledge*.
//!
//! A from-scratch zero-knowledge proving system. The roadmap is Halo2-flavored:
//!
//! 1. Prime fields (this crate, v0)
//! 2. Univariate + multilinear polynomials
//! 3. KZG and IPA polynomial commitments
//! 4. PLONK arithmetization with custom gates
//! 5. Lookup arguments (LogUp / cq)
//! 6. Recursive composition (cycle of curves)
//!
//! v0 ships the field arithmetic substrate. Everything else is built on top.

pub mod field;
pub mod fri;
pub mod hash;
pub mod merkle;
pub mod multilinear;
pub mod poly;
pub mod sumcheck;
pub mod transcript;

pub use field::{Field, Goldilocks};
pub use fri::{
    fri_fold, fri_prove, fri_prove_evals, fri_verify, fri_verify_evals, FriProof, FriProofExt,
    FriQuery, FriQueryLayer,
};

pub use merkle::{merkle_verify, MerkleOpening, MerkleTree};
pub use multilinear::MultilinearPoly;
pub use poly::{intt, ntt, Polynomial};
pub use sumcheck::{sumcheck_prove, sumcheck_verify, SumcheckProof};
pub use transcript::Transcript;
