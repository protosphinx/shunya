//! Hash interface for Merkle trees and Fiat-Shamir.
//!
//! v0.3 shipped a deliberately toy FNV-1a mixer; v0.7 swaps the
//! implementation to SHA-256 (truncated to 64 bits) so Merkle openings and
//! transcript challenges become cryptographically meaningful.
//!
//! The output type stays `u64` - downstream `merkle.rs`, `transcript.rs`,
//! and `fri.rs` see no API change. Truncating SHA-256 to 64 bits gives
//! 64-bit collision resistance, which is enough for the v0.7 demonstration.
//! v0.8 widens hash output to 32 bytes for full 128-bit collision
//! resistance (the production setting).

use crate::sha256::sha256_u64;

const TAG_ONE: u8 = 0xA1;
const TAG_PAIR: u8 = 0xB2;

/// Hash a single 64-bit value via SHA-256, domain-separated from
/// [`hash_pair`].
pub fn hash_one(x: u64) -> u64 {
    let mut buf = [0u8; 9];
    buf[0] = TAG_ONE;
    buf[1..9].copy_from_slice(&x.to_le_bytes());
    sha256_u64(&buf)
}

/// Hash a pair of 64-bit values via SHA-256.
/// `hash_pair(a, b) != hash_pair(b, a)`.
pub fn hash_pair(left: u64, right: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = TAG_PAIR;
    buf[1..9].copy_from_slice(&left.to_le_bytes());
    buf[9..17].copy_from_slice(&right.to_le_bytes());
    sha256_u64(&buf)
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
