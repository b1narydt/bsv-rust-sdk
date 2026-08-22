//! Jacobian coordinate point for efficient elliptic curve operations.
//!
//! JacobianPoint represents a point on the secp256k1 curve in Jacobian
//! coordinates (X, Y, Z) where the affine coordinates are (X/Z^2, Y/Z^3).
//! This avoids modular inversions during point addition and doubling,
//! only requiring one inversion at the final conversion to affine.

use crate::primitives::big_number::BigNumber;
use crate::primitives::curve::Curve;
use crate::primitives::reduction_context::ReductionContext;
use std::sync::Arc;

/// A point on the secp256k1 curve in Jacobian coordinates.
///
/// Affine point (x, y) is represented as (X, Y, Z) where x = X/Z^2, y = Y/Z^3.
/// The point at infinity has Z = 0.
#[derive(Clone, Debug)]
pub struct JacobianPoint {
    /// X coordinate (in reduction context).
    pub x: BigNumber,
    /// Y coordinate (in reduction context).
    pub y: BigNumber,
    /// Z coordinate (in reduction context).
    pub z: BigNumber,
    /// Reduction context reference.
    red: Arc<ReductionContext>,
}

impl JacobianPoint {
    /// Create a new Jacobian point from coordinates in the field.
    /// Coordinates should NOT already be in a reduction context.
    pub fn new(x: BigNumber, y: BigNumber, z: BigNumber) -> Self {
        let curve = Curve::secp256k1();
        let red = curve.red.clone();
        let x_red = x.to_red(red.clone());
        let y_red = y.to_red(red.clone());
        let z_red = z.to_red(red.clone());
        JacobianPoint {
            x: x_red,
            y: y_red,
            z: z_red,
            red,
        }
    }

    /// Create a Jacobian point from already-reduced coordinates.
    pub fn from_red(x: BigNumber, y: BigNumber, z: BigNumber, red: Arc<ReductionContext>) -> Self {
        JacobianPoint { x, y, z, red }
    }

    /// Create the point at infinity in Jacobian coordinates.
    pub fn infinity() -> Self {
        let curve = Curve::secp256k1();
        let red = curve.red.clone();
        let one = BigNumber::one().to_red(red.clone());
        let zero = BigNumber::zero().to_red(red.clone());
        JacobianPoint {
            x: one.clone(),
            y: one,
            z: zero,
            red,
        }
    }

    /// Create a Jacobian point from an affine (x, y) -- sets Z = 1.
    pub fn from_affine(x: &BigNumber, y: &BigNumber) -> Self {
        JacobianPoint::new(x.clone(), y.clone(), BigNumber::one())
    }

    /// Check if this is the point at infinity (Z == 0).
    pub fn is_infinity(&self) -> bool {
        self.z.from_red().is_zero()
    }

    /// Point doubling in Jacobian coordinates.
    ///
    /// Uses the formula for a = 0 (secp256k1):
    /// From hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    pub fn dbl(&self) -> JacobianPoint {
        if self.is_infinity() {
            return self.clone();
        }

        let red = &self.red;

        // A = X1^2
        let a = red.sqr(&self.x);
        // B = Y1^2
        let b = red.sqr(&self.y);
        // C = B^2
        let c = red.sqr(&b);

        // D = 2 * ((X1 + B)^2 - A - C)
        let xb = red.add(&self.x, &b);
        let xb_sq = red.sqr(&xb);
        let d = red.sub(&red.sub(&xb_sq, &a), &c);
        let d = red.add(&d, &d);

        // E = 3 * A (since a=0 for secp256k1, M = 3 * X1^2)
        let e = red.add(&a, &red.add(&a, &a));

        // F = E^2
        let f = red.sqr(&e);

        // 8 * C
        let c2 = red.add(&c, &c);
        let c4 = red.add(&c2, &c2);
        let c8 = red.add(&c4, &c4);

        // X3 = F - 2*D
        let nx = red.sub(&f, &red.add(&d, &d));

        // Y3 = E * (D - X3) - 8*C
        let ny = red.sub(&red.mul(&e, &red.sub(&d, &nx)), &c8);

        // Z3 = 2 * Y1 * Z1
        let nz = red.mul(&self.y, &self.z);
        let nz = red.add(&nz, &nz);

        JacobianPoint::from_red(nx, ny, nz, self.red.clone())
    }

    /// Point addition in Jacobian coordinates.
    ///
    /// From hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    pub fn add(&self, other: &JacobianPoint) -> JacobianPoint {
        if self.is_infinity() {
            return other.clone();
        }
        if other.is_infinity() {
            return self.clone();
        }

        let red = &self.red;

        // 12M + 4S + 7A
        let pz2 = red.sqr(&other.z);
        let z2 = red.sqr(&self.z);
        let u1 = red.mul(&self.x, &pz2);
        let u2 = red.mul(&other.x, &z2);
        let s1 = red.mul(&self.y, &red.mul(&pz2, &other.z));
        let s2 = red.mul(&other.y, &red.mul(&z2, &self.z));

        let h = red.sub(&u1, &u2);
        let r = red.sub(&s1, &s2);

        if h.from_red().is_zero() {
            if !r.from_red().is_zero() {
                return JacobianPoint::infinity();
            } else {
                return self.dbl();
            }
        }

        let h2 = red.sqr(&h);
        let h3 = red.mul(&h2, &h);
        let v = red.mul(&u1, &h2);

        // X3 = R^2 + h3 - 2*V
        // h = u1 - u2 (sign flipped from standard), so h^3 = -H^3 mod p
        // Adding h3 here is equivalent to subtracting H^3 in the standard formula
        let r2 = red.sqr(&r);
        let v2 = red.add(&v, &v);
        let nx = red.sub(&red.add(&r2, &h3), &v2);

        // Y3 = R * (V - X3) - S1 * H^3
        let ny = red.sub(&red.mul(&r, &red.sub(&v, &nx)), &red.mul(&s1, &h3));

        // Z3 = Z1 * Z2 * H
        let nz = red.mul(&red.mul(&self.z, &other.z), &h);

        JacobianPoint::from_red(nx, ny, nz, self.red.clone())
    }

    /// Negate a Jacobian point (negate the Y coordinate).
    pub fn neg(&self) -> JacobianPoint {
        if self.is_infinity() {
            return self.clone();
        }
        let ny = self.red.neg(&self.y);
        JacobianPoint::from_red(self.x.clone(), ny, self.z.clone(), self.red.clone())
    }

    /// Convert to affine coordinates (x, y).
    /// Returns (x, y) BigNumbers NOT in a reduction context.
    /// Panics if this is the point at infinity -- callers should check first.
    pub fn to_affine(&self) -> (BigNumber, BigNumber) {
        assert!(
            !self.is_infinity(),
            "cannot convert point at infinity to affine"
        );
        let red = &self.red;

        let z_inv = red.invm(&self.z);
        let z_inv2 = red.sqr(&z_inv);
        let z_inv3 = red.mul(&z_inv2, &z_inv);

        let x = red.mul(&self.x, &z_inv2).from_red();
        let y = red.mul(&self.y, &z_inv3).from_red();

        (x, y)
    }

    /// Scalar multiplication using the double-and-add algorithm.
    /// k must be a positive BigNumber.
    pub fn mul(&self, k: &BigNumber) -> JacobianPoint {
        if k.is_zero() || self.is_infinity() {
            return JacobianPoint::infinity();
        }

        let bits = k.bit_length();
        let mut result = JacobianPoint::infinity();
        let mut addend = self.clone();

        for i in 0..bits {
            if k.testn(i) {
                result = result.add(&addend);
            }
            addend = addend.dbl();
        }

        result
    }

    /// Windowed NAF scalar multiplication for better performance.
    /// Uses a window size of 5 for optimal performance on 256-bit scalars.
    pub fn mul_wnaf(&self, k: &BigNumber) -> JacobianPoint {
        if k.is_zero() || self.is_infinity() {
            return JacobianPoint::infinity();
        }

        let window = 4u32;
        let tbl_size = 1usize << (window - 1); // 8 entries

        // Precompute odd multiples: [1*P, 3*P, 5*P, ..., (2*tbl_size-1)*P]
        let mut tbl = Vec::with_capacity(tbl_size);
        tbl.push(self.clone());
        let two_p = self.dbl();
        for i in 1..tbl_size {
            tbl.push(tbl[i - 1].add(&two_p));
        }

        // Pre-negate all table entries to avoid calling neg() on every negative wNAF digit
        let neg_tbl: Vec<JacobianPoint> = tbl.iter().map(|p| p.neg()).collect();

        // Build wNAF representation
        let wnaf = Self::build_wnaf(k, window);

        // Accumulate from MSB to LSB
        let mut q = JacobianPoint::infinity();
        for i in (0..wnaf.len()).rev() {
            q = q.dbl();
            let di = wnaf[i];
            if di != 0 {
                let idx = (di.unsigned_abs() as usize) >> 1;
                if di > 0 {
                    q = q.add(&tbl[idx]);
                } else {
                    q = q.add(&neg_tbl[idx]);
                }
            }
        }

        q
    }

    /// Build wNAF representation of scalar k with given window size.
    fn build_wnaf(k: &BigNumber, window: u32) -> Vec<i32> {
        let mut wnaf: Vec<i32> = Vec::new();
        let mut k_tmp = k.clone();
        let w_val = 1i64 << window;
        let w_half = w_val >> 1;

        while !k_tmp.is_zero() {
            if k_tmp.is_odd() {
                let mod_val = k_tmp.andln(window + 1) as i64;
                let z = if mod_val >= w_half {
                    mod_val - w_val
                } else {
                    mod_val
                };
                wnaf.push(z as i32);
                if z < 0 {
                    k_tmp = k_tmp.addn(-z);
                } else if z > 0 {
                    k_tmp = k_tmp.subn(z);
                }
            } else {
                wnaf.push(0);
            }
            k_tmp.iushrn(1);
        }

        wnaf
    }

    /// Shamir's trick: simultaneous scalar multiplication k1*P1 + k2*P2.
    ///
    /// Uses a single pass of doublings shared between both scalars, which is
    /// roughly 1.5x faster than two independent mul_wnaf calls.
    ///
    /// p1_table: precomputed wNAF table for P1 (e.g., BasePoint::table())
    /// k2: scalar for P2
    /// p2: the second point
    pub fn shamir_mul_wnaf(
        k1: &BigNumber,
        p1_table: &[JacobianPoint],
        k2: &BigNumber,
        p2: &JacobianPoint,
    ) -> JacobianPoint {
        if k1.is_zero() && k2.is_zero() {
            return JacobianPoint::infinity();
        }

        let window = 4u32;
        let tbl_size = 1usize << (window - 1); // 8 entries

        // Build precomputed table for p2
        let mut tbl2 = Vec::with_capacity(tbl_size);
        tbl2.push(p2.clone());
        let two_p2 = p2.dbl();
        for i in 1..tbl_size {
            tbl2.push(tbl2[i - 1].add(&two_p2));
        }

        // Pre-negate both tables
        let neg_tbl1: Vec<JacobianPoint> = p1_table.iter().map(|p| p.neg()).collect();
        let neg_tbl2: Vec<JacobianPoint> = tbl2.iter().map(|p| p.neg()).collect();

        // Build wNAF for both scalars
        let wnaf1 = Self::build_wnaf(k1, window);
        let wnaf2 = Self::build_wnaf(k2, window);

        let max_len = wnaf1.len().max(wnaf2.len());

        // Single pass from MSB to LSB with shared doublings
        let mut q = JacobianPoint::infinity();
        for i in (0..max_len).rev() {
            q = q.dbl();

            // Add contribution from k1
            let d1 = if i < wnaf1.len() { wnaf1[i] } else { 0 };
            if d1 != 0 {
                let idx = (d1.unsigned_abs() as usize) >> 1;
                if d1 > 0 {
                    q = q.add(&p1_table[idx]);
                } else {
                    q = q.add(&neg_tbl1[idx]);
                }
            }

            // Add contribution from k2
            let d2 = if i < wnaf2.len() { wnaf2[i] } else { 0 };
            if d2 != 0 {
                let idx = (d2.unsigned_abs() as usize) >> 1;
                if d2 > 0 {
                    q = q.add(&tbl2[idx]);
                } else {
                    q = q.add(&neg_tbl2[idx]);
                }
            }
        }

        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g_jacobian() -> JacobianPoint {
        let curve = Curve::secp256k1();
        JacobianPoint::from_affine(&curve.g_x, &curve.g_y)
    }

    #[test]
    fn test_jacobian_infinity() {
        let inf = JacobianPoint::infinity();
        assert!(inf.is_infinity());
    }

    #[test]
    fn test_jacobian_not_infinity() {
        let g = g_jacobian();
        assert!(!g.is_infinity());
    }

    #[test]
    fn test_jacobian_dbl_matches_affine() {
        let g = g_jacobian();
        let two_g = g.dbl();
        let (x, y) = two_g.to_affine();
        assert_eq!(
            x.to_hex(),
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        assert_eq!(
            y.to_hex(),
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
        );
    }

    #[test]
    fn test_jacobian_add_g_plus_g() {
        let g = g_jacobian();
        let two_g = g.add(&g);
        let (x, y) = two_g.to_affine();
        assert_eq!(
            x.to_hex(),
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        assert_eq!(
            y.to_hex(),
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
        );
    }

    #[test]
    fn test_jacobian_add_g_plus_2g() {
        let g = g_jacobian();
        let two_g = g.dbl();
        let three_g = g.add(&two_g);
        let (x, y) = three_g.to_affine();
        assert_eq!(
            x.to_hex(),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        assert_eq!(
            y.to_hex(),
            "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"
        );
    }

    #[test]
    fn test_jacobian_add_identity() {
        let g = g_jacobian();
        let inf = JacobianPoint::infinity();

        // G + O = G
        let r1 = g.add(&inf);
        let (x1, y1) = r1.to_affine();
        let curve = Curve::secp256k1();
        assert_eq!(x1.cmp(&curve.g_x), 0);
        assert_eq!(y1.cmp(&curve.g_y), 0);

        // O + G = G
        let r2 = inf.add(&g);
        let (x2, y2) = r2.to_affine();
        assert_eq!(x2.cmp(&curve.g_x), 0);
        assert_eq!(y2.cmp(&curve.g_y), 0);
    }

    #[test]
    fn test_jacobian_neg() {
        let g = g_jacobian();
        let neg_g = g.neg();
        // G + (-G) = O
        let result = g.add(&neg_g);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_jacobian_mul_1() {
        let g = g_jacobian();
        let k = BigNumber::one();
        let result = g.mul(&k);
        let (x, y) = result.to_affine();
        let curve = Curve::secp256k1();
        assert_eq!(x.cmp(&curve.g_x), 0);
        assert_eq!(y.cmp(&curve.g_y), 0);
    }

    #[test]
    fn test_jacobian_mul_2() {
        let g = g_jacobian();
        let k = BigNumber::from_number(2);
        let result = g.mul(&k);
        let (x, y) = result.to_affine();
        assert_eq!(
            x.to_hex(),
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        assert_eq!(
            y.to_hex(),
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
        );
    }

    #[test]
    fn test_jacobian_mul_n_is_infinity() {
        let g = g_jacobian();
        let curve = Curve::secp256k1();
        let result = g.mul(&curve.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_jacobian_mul_wnaf_matches() {
        let g = g_jacobian();
        let k = BigNumber::from_number(7);
        let r1 = g.mul(&k);
        let r2 = g.mul_wnaf(&k);

        if r1.is_infinity() {
            assert!(r2.is_infinity());
        } else {
            let (x1, y1) = r1.to_affine();
            let (x2, y2) = r2.to_affine();
            assert_eq!(x1.cmp(&x2), 0);
            assert_eq!(y1.cmp(&y2), 0);
        }
    }

    #[test]
    fn test_jacobian_mul_wnaf_10g() {
        let g = g_jacobian();
        let k = BigNumber::from_number(10);
        let result = g.mul_wnaf(&k);
        let (x, y) = result.to_affine();
        assert_eq!(
            x.to_hex(),
            "a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
        );
        assert_eq!(
            y.to_hex(),
            "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7"
        );
    }
}
