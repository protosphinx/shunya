//! Prime field arithmetic.
//!
//! v0 implements the Goldilocks field, `p = 2^64 - 2^32 + 1`. Chosen for its
//! NTT-friendliness - the multiplicative group has order
//! `2^32 · 3 · 5 · 17 · 257 · 65537`, so it admits FFTs of every power-of-two
//! length up to 2^32 - and for cheap reduction. Used by Plonky2, Starks, and
//! most modern small-field SNARK stacks.
//!
//! v0.1 ships the fast Goldilocks reduction (decompose product into limbs,
//! exploit `2^64 ≡ 2^32 - 1 (mod p)`). Cross-tested against the naive
//! `% P` path for ten thousand pseudo-random products.

use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Minimal prime-field interface. Future: extension fields, batch inversion.
pub trait Field:
    Copy
    + Clone
    + PartialEq
    + Eq
    + fmt::Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;

    fn pow(self, exp: u64) -> Self;
    fn inv(self) -> Option<Self>;
    fn square(self) -> Self {
        self * self
    }
}

/// Goldilocks prime: `p = 2^64 - 2^32 + 1`.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// `2^32 - 1`. Equal to `2^64 mod p`, which makes it the workhorse constant in
/// the fast reduction.
pub const EPSILON: u64 = 0xFFFF_FFFF;

/// Element of the Goldilocks field, stored canonically in `[0, P)`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Goldilocks(u64);

impl Goldilocks {
    pub const fn new(v: u64) -> Self {
        Self(if v >= P { v - P } else { v })
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Reduce a 128-bit product modulo `P`.
    ///
    /// Decompose `x = x_lo + x_hi · 2^64` with `x_hi = x_hh · 2^32 + x_hl`.
    /// Using `2^64 ≡ 2^32 - 1 (mod p)` and `2^96 ≡ -1 (mod p)`:
    ///
    /// ```text
    /// x ≡ x_lo + x_hl · (2^32 - 1) - x_hh   (mod p)
    /// ```
    ///
    /// Each subtraction-with-borrow is corrected by subtracting `EPSILON`,
    /// since `+p ≡ -EPSILON (mod 2^64)`. One final `>= P` correction lands
    /// the result in `[0, P)`.
    pub fn reduce_u128(x: u128) -> Self {
        let x_lo = x as u64;
        let x_hi = (x >> 64) as u64;
        let x_hh = x_hi >> 32;
        let x_hl = x_hi & EPSILON;

        let (t0, borrow) = x_lo.overflowing_sub(x_hh);
        let t0 = if borrow { t0.wrapping_sub(EPSILON) } else { t0 };

        // x_hl < 2^32 and EPSILON < 2^32, so the product fits in u64.
        let t1 = x_hl.wrapping_mul(EPSILON);

        let (t2, carry) = t0.overflowing_add(t1);
        let t2 = if carry { t2.wrapping_add(EPSILON) } else { t2 };

        if t2 >= P {
            Self(t2 - P)
        } else {
            Self(t2)
        }
    }
}

impl fmt::Display for Goldilocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for Goldilocks {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (sum, carry) = self.0.overflowing_add(rhs.0);
        let (red, borrow) = sum.overflowing_sub(P);
        if carry || !borrow {
            Self(red)
        } else {
            Self(sum)
        }
    }
}

impl Sub for Goldilocks {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (diff, borrow) = self.0.overflowing_sub(rhs.0);
        if borrow {
            Self(diff.wrapping_add(P))
        } else {
            Self(diff)
        }
    }
}

impl Neg for Goldilocks {
    type Output = Self;
    fn neg(self) -> Self {
        if self.0 == 0 {
            self
        } else {
            Self(P - self.0)
        }
    }
}

impl Mul for Goldilocks {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::reduce_u128((self.0 as u128) * (rhs.0 as u128))
    }
}

impl AddAssign for Goldilocks {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Goldilocks {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl MulAssign for Goldilocks {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Field for Goldilocks {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn pow(self, mut exp: u64) -> Self {
        let mut acc = Self::ONE;
        let mut base = self;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc * base;
            }
            base = base * base;
            exp >>= 1;
        }
        acc
    }

    fn inv(self) -> Option<Self> {
        if self == Self::ZERO {
            None
        } else {
            // Fermat: a^(p-2) ≡ a^-1 (mod p).
            Some(self.pow(P - 2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_wraps_at_modulus() {
        let a = Goldilocks::new(P - 1);
        let b = Goldilocks::new(2);
        assert_eq!((a + b).raw(), 1);
    }

    #[test]
    fn sub_underflows_to_modulus() {
        let a = Goldilocks::new(1);
        let b = Goldilocks::new(2);
        assert_eq!((a - b).raw(), P - 1);
    }

    #[test]
    fn neg_of_zero_is_zero() {
        assert_eq!(-Goldilocks::ZERO, Goldilocks::ZERO);
    }

    #[test]
    fn neg_then_add_is_zero() {
        let a = Goldilocks::new(0xDEAD_BEEF_CAFE);
        assert_eq!(a + (-a), Goldilocks::ZERO);
    }

    #[test]
    fn mul_distributes_over_add() {
        let a = Goldilocks::new(7);
        let b = Goldilocks::new(13);
        let c = Goldilocks::new(101);
        assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let a = Goldilocks::new(3);
        let mut acc = Goldilocks::ONE;
        for _ in 0..17 {
            acc = acc * a;
        }
        assert_eq!(a.pow(17), acc);
    }

    #[test]
    fn inv_round_trips() {
        let a = Goldilocks::new(0x1234_5678_9ABC);
        let inv = a.inv().unwrap();
        assert_eq!(a * inv, Goldilocks::ONE);
    }

    #[test]
    fn inv_of_zero_is_none() {
        assert!(Goldilocks::ZERO.inv().is_none());
    }

    #[test]
    fn fermat_little_theorem() {
        // a^p ≡ a (mod p) for all a.
        for v in [1u64, 2, 3, 0xFEED_FACE, P - 1] {
            let a = Goldilocks::new(v);
            assert_eq!(a.pow(P), a);
        }
    }

    #[test]
    fn fast_reduction_matches_naive() {
        // Pseudo-random LCG; cross-check fast `reduce_u128` against `% P`.
        let mut s: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let next = |s: &mut u64| -> u64 {
            *s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *s
        };
        for _ in 0..10_000 {
            let a = next(&mut s) % P;
            let b = next(&mut s) % P;
            let prod = (a as u128) * (b as u128);
            let fast = Goldilocks::reduce_u128(prod).raw();
            let slow = (prod % P as u128) as u64;
            assert_eq!(fast, slow, "mismatch a={} b={}", a, b);
        }
    }

    #[test]
    fn fast_reduction_handles_extremes() {
        // Edge cases: zeros, ones, p-1, max u64.
        let extremes = [0u64, 1, 2, P - 2, P - 1, u64::MAX % P];
        for &a in &extremes {
            for &b in &extremes {
                let prod = (a as u128) * (b as u128);
                let fast = Goldilocks::reduce_u128(prod).raw();
                let slow = (prod % P as u128) as u64;
                assert_eq!(fast, slow, "extreme mismatch a={} b={}", a, b);
            }
        }
    }
}
