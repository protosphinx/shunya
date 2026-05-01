//! Toy hash function for Merkle trees and Fiat-Shamir.
//!
//! v0.3 uses a deliberately-simple hash: an FNV-1a accumulator chained
//! through a few rotation-and-multiply rounds. It is *not* cryptographically
//! secure. Real hashes (BLAKE3 for off-chain, Poseidon or Rescue for
//! recursion-friendly) land in v0.5 alongside the lookup arguments.
//!
//! What this module *is* good for: validating the protocol structure of
//! Merkle commitments and FRI without pulling in a hash dependency. Every
//! consumer treats hash output as opaque `u64`, so swapping in a real hash
//! later is a one-file change.

const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;

fn absorb_byte(state: u64, b: u8) -> u64 {
    let s = state ^ (b as u64);
    s.wrapping_mul(FNV_PRIME)
}

fn finalize(mut s: u64) -> u64 {
    for _ in 0..3 {
        s = s.wrapping_mul(FNV_PRIME);
        s ^= s.rotate_left(17);
    }
    s
}

/// Hash a single 64-bit value.
pub fn hash_one(x: u64) -> u64 {
    let mut s = FNV_OFFSET;
    for b in x.to_le_bytes() {
        s = absorb_byte(s, b);
    }
    // Domain separation tag for unary inputs.
    s = absorb_byte(s, 0xA1);
    finalize(s)
}

/// Hash a pair of 64-bit values, in order. `hash_pair(a, b) != hash_pair(b, a)`.
pub fn hash_pair(left: u64, right: u64) -> u64 {
    let mut s = FNV_OFFSET;
    for b in left.to_le_bytes() {
        s = absorb_byte(s, b);
    }
    // Domain separation between left and right halves.
    s = absorb_byte(s, 0xB2);
    for b in right.to_le_bytes() {
        s = absorb_byte(s, b);
    }
    finalize(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_one_is_deterministic() {
        assert_eq!(hash_one(7), hash_one(7));
        assert_ne!(hash_one(7), hash_one(8));
    }

    #[test]
    fn hash_pair_is_deterministic_and_ordered() {
        assert_eq!(hash_pair(1, 2), hash_pair(1, 2));
        assert_ne!(hash_pair(1, 2), hash_pair(2, 1));
        assert_ne!(hash_pair(0, 0), hash_pair(0, 1));
    }

    #[test]
    fn hash_one_and_hash_pair_are_distinct() {
        // Domain separation: hash_one(x) should not collide with hash_pair(x, 0).
        assert_ne!(hash_one(42), hash_pair(42, 0));
    }
}
