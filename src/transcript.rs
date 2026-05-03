//! Toy Fiat–Shamir transcript.
//!
//! v0.2 ships an explicitly toy transcript: a 64-bit accumulator updated by
//! a multiplicative-XOR step (FNV-1a-flavored). It is *not* cryptographically
//! secure - collision-resistance hasn't been argued, distinguishability from
//! random is trivially false, and the state space is one Goldilocks element.
//!
//! What it *does* do correctly is the protocol shape: deterministic challenges
//! that depend on every value previously appended. That's enough to validate
//! the soundness of the higher-level sumcheck construction with property tests
//! and to swap in a real sponge later (Poseidon, Rescue) without touching the
//! protocol code.
//!
//! Real Fiat–Shamir lands at v0.4 alongside the PLONK arithmetization, where
//! the choice of hash function actually affects the verifier circuit.

use crate::field::Goldilocks;

const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;

#[derive(Debug, Clone)]
pub struct Transcript {
    state: u64,
}

impl Transcript {
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut s = Self { state: FNV_OFFSET };
        for &b in domain_separator {
            s.absorb_byte(b);
        }
        s
    }

    fn absorb_byte(&mut self, b: u8) {
        self.state ^= b as u64;
        self.state = self.state.wrapping_mul(FNV_PRIME);
    }

    pub fn append(&mut self, x: Goldilocks) {
        for b in x.raw().to_le_bytes() {
            self.absorb_byte(b);
        }
    }

    /// Squeeze the next challenge.
    pub fn challenge(&mut self) -> Goldilocks {
        // Domain-separate the squeeze step.
        self.absorb_byte(0xCC);
        // Run a few extra rounds to mix.
        for _ in 0..3 {
            self.state = self.state.wrapping_mul(FNV_PRIME);
            self.state ^= self.state >> 32;
        }
        Goldilocks::new(self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_same_inputs_yield_same_challenge() {
        let mut t1 = Transcript::new(b"shunya-test");
        let mut t2 = Transcript::new(b"shunya-test");
        t1.append(Goldilocks::new(7));
        t1.append(Goldilocks::new(11));
        t2.append(Goldilocks::new(7));
        t2.append(Goldilocks::new(11));
        assert_eq!(t1.challenge(), t2.challenge());
    }

    #[test]
    fn different_inputs_diverge() {
        let mut t1 = Transcript::new(b"shunya-test");
        let mut t2 = Transcript::new(b"shunya-test");
        t1.append(Goldilocks::new(7));
        t2.append(Goldilocks::new(8));
        assert_ne!(t1.challenge(), t2.challenge());
    }

    #[test]
    fn different_domain_separators_diverge() {
        let mut t1 = Transcript::new(b"shunya-A");
        let mut t2 = Transcript::new(b"shunya-B");
        assert_ne!(t1.challenge(), t2.challenge());
    }

    #[test]
    fn challenges_chain_forward() {
        // A second challenge depends on the first.
        let mut t = Transcript::new(b"shunya-test");
        let c1 = t.challenge();
        let c2 = t.challenge();
        assert_ne!(c1, c2);
    }
}
