//! Base point (generator) operations with precomputed window tables.
//!
//! BasePoint provides optimized scalar multiplication of the secp256k1
//! generator point G using precomputed tables. This is significantly
//! faster than general point multiplication for operations like key
//! generation (privkey * G).

use crate::primitives::big_number::BigNumber;
use crate::primitives::curve::Curve;
use crate::primitives::jacobian_point::JacobianPoint;
use crate::primitives::point::Point;

/// The secp256k1 base point (generator) with precomputed multiplication tables.
///
/// Uses a windowed precomputation approach: stores [1*G, 2*G, ..., 2^w * G]
/// for a chosen window size w, enabling faster scalar multiplication via
/// the wNAF (windowed non-adjacent form) method.
pub struct BasePoint {
    /// Window size for precomputation.
    window: u32,
    /// Precomputed odd multiples of G: [G, 3G, 5G, ..., (2^(w-1)-1)*2*G + G].
    table: Vec<JacobianPoint>,
    /// Pre-negated table entries for wNAF negative digits.
    neg_table: Vec<JacobianPoint>,
}

/// Singleton BasePoint instance.
static BASE_POINT_INIT: std::sync::OnceLock<BasePoint> = std::sync::OnceLock::new();

impl BasePoint {
    /// Get the singleton precomputed base point.
    pub fn instance() -> &'static BasePoint {
        BASE_POINT_INIT.get_or_init(|| {
            let window = 5u32;
            let curve = Curve::secp256k1();
            let g = JacobianPoint::from_affine(&curve.g_x, &curve.g_y);

            let tbl_size = 1usize << (window - 1); // 16 entries for w=5
            let mut table = Vec::with_capacity(tbl_size);
            table.push(g.clone());

            let two_g = g.dbl();
            for i in 1..tbl_size {
                table.push(table[i - 1].add(&two_g));
            }

            let neg_table: Vec<JacobianPoint> = table.iter().map(|p| p.neg()).collect();
            BasePoint {
                window,
                table,
                neg_table,
            }
        })
    }

    /// Access the precomputed table as a slice (for Shamir's trick).
    pub fn table(&self) -> &[JacobianPoint] {
        &self.table
    }

    /// Multiply the base point G by scalar k.
    /// This uses the precomputed wNAF table for efficiency.
    pub fn mul(&self, k: &BigNumber) -> Point {
        if k.is_zero() {
            return Point::infinity();
        }

        let is_neg = k.is_neg();
        let k_abs = if is_neg { k.neg() } else { k.clone() };

        // Reduce k mod n
        let curve = Curve::secp256k1();
        let k_mod = k_abs.umod(&curve.n).unwrap_or(k_abs);

        if k_mod.is_zero() {
            return Point::infinity();
        }

        // Build wNAF representation
        let window = self.window;
        let mut wnaf: Vec<i32> = Vec::new();
        let mut k_tmp = k_mod;
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

        // Accumulate from MSB to LSB using cached neg table
        let mut q = JacobianPoint::infinity();
        for i in (0..wnaf.len()).rev() {
            q = q.dbl();
            let di = wnaf[i];
            if di != 0 {
                let idx = (di.unsigned_abs() as usize) >> 1;
                if di > 0 {
                    q = q.add(&self.table[idx]);
                } else {
                    q = q.add(&self.neg_table[idx]);
                }
            }
        }

        if q.is_infinity() {
            return Point::infinity();
        }

        let (x, y) = q.to_affine();
        let point = Point::new(x, y);

        if is_neg {
            point.negate()
        } else {
            point
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_point_mul_1() {
        let bp = BasePoint::instance();
        let result = bp.mul(&BigNumber::one());
        let curve = Curve::secp256k1();
        assert_eq!(result.x.cmp(&curve.g_x), 0);
        assert_eq!(result.y.cmp(&curve.g_y), 0);
    }

    #[test]
    fn test_base_point_mul_2() {
        let bp = BasePoint::instance();
        let result = bp.mul(&BigNumber::from_number(2));
        assert_eq!(
            result.x.to_hex(),
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
    }

    #[test]
    fn test_base_point_mul_n_is_infinity() {
        let bp = BasePoint::instance();
        let curve = Curve::secp256k1();
        let result = bp.mul(&curve.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_base_point_mul_matches_point_mul() {
        let bp = BasePoint::instance();
        let curve = Curve::secp256k1();
        let g = curve.generator();

        for k_val in [3, 7, 10, 42, 100] {
            let k = BigNumber::from_number(k_val);
            let bp_result = bp.mul(&k);
            let p_result = g.mul(&k);
            assert!(
                bp_result.eq(&p_result),
                "BasePoint.mul mismatch for k={k_val}"
            );
        }
    }

    #[test]
    fn test_base_point_mul_known_vectors() {
        let bp = BasePoint::instance();
        let expected = vec![
            (
                5,
                "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
                "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6",
            ),
            (
                10,
                "a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
            ),
        ];

        for (k, ex, ey) in expected {
            let result = bp.mul(&BigNumber::from_number(k));
            assert_eq!(result.x.to_hex(), ex, "x mismatch for k={k}");
            assert_eq!(result.y.to_hex(), ey, "y mismatch for k={k}");
        }
    }

    #[test]
    fn test_base_point_mul_zero() {
        let bp = BasePoint::instance();
        let result = bp.mul(&BigNumber::zero());
        assert!(result.is_infinity());
    }

    #[test]
    fn test_base_point_mul_large_scalar() {
        // Use a large random-ish scalar
        let bp = BasePoint::instance();
        let k =
            BigNumber::from_hex("deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567")
                .unwrap();
        let result = bp.mul(&k);
        assert!(!result.is_infinity());
        assert!(result.validate());
    }
}
