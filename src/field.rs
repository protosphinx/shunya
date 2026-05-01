//! Prime field arithmetic.
//!
//! v0 implements the Goldilocks field, `p = 2^64 - 2^32 + 1`. Chosen for its
//! NTT-friendliness — the multiplicative group has order
//! `2^32 · 3 · 5 · 17 · 257 · 65537`, so it admits FFTs of every power-of-two
//! length up to 2^32 — and for cheap reduction. Used by Plonky2, Starks, and
//! most modern small-field SNARK stacks.
//!
//! v0 uses a straightforward `% P` reduction in `Mul`. The fast Goldilocks
//! reduction (decompose product into limbs, exploit `2^64 ≡ 2^32 - 1 (mod p)`)
//! is a v1 optimization tracked in `GOALS.md`.

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
        let prod = (self.0 as u128) * (rhs.0 as u128);
        Self((prod % (P as u128)) as u64)
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
}
